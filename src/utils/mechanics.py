#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pure-Python mechanical VMCore analysis helpers.

This module intentionally avoids importing the LangGraph/react stack so that
crash subprocess tooling can run independently of LLM / graph dependencies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping

_HEX = r"(?:0x)?[0-9a-fA-F]+"

# Crash rd output line parsing
_RD_LINE_RE = re.compile(rf"^\s*(?P<address>{_HEX})\s*:\s*(?P<words>.*)$")
_RD_WORD_RE = re.compile(r"^[0-9a-fA-F]{1,16}$")

# kmem / vtop parsing
_KMEM_CACHE_HEADER_RE = re.compile(
    r"^\s*CACHE\s+OBJSIZE\s+ALLOCATED\s+TOTAL\s+SLABS\s+SSIZE\s+NAME\s*$",
    re.IGNORECASE,
)
_KMEM_CACHE_ROW_RE = re.compile(
    r"^\s*(?P<cache>(?:0x)?[0-9a-fA-F]{8,16})\s+"
    r"(?P<objsize>\d+)\s+"
    r"(?P<allocated>\d+)\s+"
    r"(?P<total>\d+)\s+"
    r"(?P<slabs>\d+)\s+"
    r"(?P<ssize>\S+)\s+"
    r"(?P<name>\S+)\s*$"
)
_KMEM_SLAB_ROW_RE = re.compile(
    r"^\s*(?P<slab>(?:0x)?[0-9a-fA-F]{8,16})\s+"
    r"(?P<memory>(?:0x)?[0-9a-fA-F]{8,16})\s+"
    r"(?P<node>\d+)\s+"
    r"(?P<total>\d+)\s+"
    r"(?P<allocated>\d+)\s+"
    r"(?P<free>\d+)\s*$"
)
_KMEM_SLOT_LINE_RE = re.compile(
    r"^\s*(?:\[\s*(?P<allocated>(?:0x)?[0-9a-fA-F]{8,16})\s*\]|"
    r"(?P<free>(?:0x)?[0-9a-fA-F]{8,16})(?:\s+\((?P<note>[^)]+)\))?)\s*$"
)
_VTOP_HEADER_RE = re.compile(r"^\s*VIRTUAL\s+PHYSICAL\s*$", re.IGNORECASE)
_VTOP_ROW_RE = re.compile(
    r"^\s*(?P<virtual>(?:0x)?[0-9a-fA-F]{8,16})\s+"
    r"(?P<physical>(?:0x)?[0-9a-fA-F]+)\s*$"
)
_VTOP_PAGE_ROW_RE = re.compile(
    r"^\s*(?P<page>(?:0x)?[0-9a-fA-F]{8,16})\s+"
    r"(?P<phys_base>(?:0x)?[0-9a-fA-F]+)\s+"
    r"(?P<mapping>\S+)\s+"
    r"(?P<index>\S+)\s+"
    r"(?P<cnt>\d+)\s+"
    r"(?P<flags>.+?)\s*$"
)

_WORD_SIZE = 8


@dataclass(frozen=True)
class MemoryRead:
    address: int
    words: tuple[int, ...]


@dataclass(frozen=True)
class SlabObjectInfo:
    cache_address: int
    cache_name: str
    obj_size: int
    slab_struct_address: int
    slab_memory_base: int
    total_objects: int
    allocated_objects: int
    free_objects: int
    slot_address: int
    allocation_state: str
    slot_index: int
    slot_offset_in_slab: int
    slot_end: int
    prev_slot: int | None
    next_slot: int | None
    note: str = ""


@dataclass(frozen=True)
class VtopTranslation:
    virtual_address: int
    physical_address: int
    page_offset: int
    linear_map_delta: int
    page_struct_address: int | None = None
    page_physical_base: int | None = None
    page_flags: str = ""


@dataclass(frozen=True)
class MemoryBlockCorrelation:
    low_address: int
    high_address: int
    address_delta: int
    matching_words: int
    exact_match_bytes: int
    first_diff_offset: int | None
    low_diff_word: int | None
    high_diff_word: int | None
    stride: int = 128
    spanned_slots: int = 1


def _to_address(text: str) -> int | None:
    token = text.strip()
    if not token:
        return None
    try:
        return int(token, 0) if token.lower().startswith("0x") else int(token, 16)
    except ValueError:
        return None


_INT_LITERAL_RE = re.compile(r"(?:0[xX][0-9A-Fa-f]+|[0-9]+)")


def parse_int_literal(token: str) -> int | None:
    """Parse a decimal or 0x-prefixed integer literal.

    Unlike ``int(token, 0)`` this accepts leading-zero decimals such as
    ``0128`` (treated as base 10) and rejects malformed tokens without raising.
    """

    text = str(token).strip()
    if not _INT_LITERAL_RE.fullmatch(text):
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None


def parse_memory_reads(text: str) -> list[MemoryRead]:
    snapshots: list[MemoryRead] = []
    start: int | None = None
    words: list[int] = []

    def _flush() -> None:
        if start is not None and words:
            snapshots.append(MemoryRead(address=start, words=tuple(words)))

    for line in text.splitlines():
        match = _RD_LINE_RE.match(line)
        if match is None:
            continue
        address = _to_address(match.group("address"))
        if address is None:
            continue
        line_words: list[int] = []
        for token in match.group("words").split():
            if _RD_WORD_RE.match(token) is None:
                break
            line_words.append(int(token, 16))
        if not line_words:
            continue

        if start is not None and address == start + len(words) * _WORD_SIZE:
            words.extend(line_words)
            continue

        _flush()
        start = address
        words = list(line_words)

    _flush()
    return snapshots


def parse_kmem_slab_outputs(text: str) -> list[SlabObjectInfo]:
    if not isinstance(text, str) or not text:
        return []

    results: list[SlabObjectInfo] = []
    seen: set[tuple[int, int, str]] = set()
    lines = text.splitlines()

    current_cache_addr: int | None = None
    current_cache_name: str = ""
    current_obj_size: int = 0
    current_slab_addr: int | None = None
    current_memory_base: int | None = None
    current_total: int = 0
    current_allocated: int = 0
    current_free: int = 0
    in_slot_section = False

    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if _KMEM_CACHE_HEADER_RE.match(line):
            in_slot_section = False
            if idx + 1 < len(lines):
                cache_match = _KMEM_CACHE_ROW_RE.match(lines[idx + 1])
                if cache_match:
                    current_cache_addr = int(cache_match.group("cache"), 16)
                    current_obj_size = int(cache_match.group("objsize"), 10)
                    current_cache_name = cache_match.group("name")
                    idx += 2
                    continue

        slab_match = _KMEM_SLAB_ROW_RE.match(line)
        if slab_match and current_cache_addr is not None and current_obj_size > 0:
            current_slab_addr = int(slab_match.group("slab"), 16)
            current_memory_base = int(slab_match.group("memory"), 16)
            current_total = int(slab_match.group("total"), 10)
            current_allocated = int(slab_match.group("allocated"), 10)
            current_free = int(slab_match.group("free"), 10)
            in_slot_section = False
            idx += 1
            continue

        if "FREE / [ALLOCATED]" in line.upper():
            in_slot_section = True
            idx += 1
            continue

        if (
            in_slot_section
            and current_cache_addr is not None
            and current_slab_addr is not None
            and current_memory_base is not None
            and current_obj_size > 0
        ):
            slot_match = _KMEM_SLOT_LINE_RE.match(line)
            if slot_match:
                alloc_tok = slot_match.group("allocated")
                free_tok = slot_match.group("free")
                raw_slot = alloc_tok or free_tok
                if raw_slot:
                    slot_addr = int(raw_slot, 16)
                    state = "allocated" if alloc_tok else "free"
                    key = (current_cache_addr, slot_addr, state)
                    if key not in seen and slot_addr >= current_memory_base:
                        seen.add(key)
                        offset_in_slab = slot_addr - current_memory_base
                        slot_idx = offset_in_slab // current_obj_size
                        slot_base = current_memory_base + slot_idx * current_obj_size
                        prev_slot = (
                            slot_base - current_obj_size if slot_idx > 0 else None
                        )
                        next_slot = (
                            slot_base + current_obj_size
                            if (current_total <= 0 or slot_idx + 1 < current_total)
                            else None
                        )
                        results.append(
                            SlabObjectInfo(
                                cache_address=current_cache_addr,
                                cache_name=current_cache_name,
                                obj_size=current_obj_size,
                                slab_struct_address=current_slab_addr,
                                slab_memory_base=current_memory_base,
                                total_objects=current_total,
                                allocated_objects=current_allocated,
                                free_objects=current_free,
                                slot_address=slot_base,
                                allocation_state=state,
                                slot_index=slot_idx,
                                slot_offset_in_slab=offset_in_slab,
                                slot_end=slot_base + current_obj_size,
                                prev_slot=prev_slot,
                                next_slot=next_slot,
                                note=(slot_match.group("note") or "").strip(),
                            )
                        )
                idx += 1
                continue
            if line.strip() and not line.startswith(" "):
                in_slot_section = False

        idx += 1

    return results


def parse_vtop_outputs(text: str) -> list[VtopTranslation]:
    if not isinstance(text, str) or not text:
        return []

    lines = text.splitlines()
    results: list[VtopTranslation] = []
    seen: set[tuple[int, int]] = set()

    idx = 0
    while idx < len(lines):
        if _VTOP_HEADER_RE.match(lines[idx]) and idx + 1 < len(lines):
            row_match = _VTOP_ROW_RE.match(lines[idx + 1])
            if row_match:
                vaddr = int(row_match.group("virtual"), 16)
                paddr = int(row_match.group("physical"), 16)
                page_struct: int | None = None
                page_phys_base: int | None = None
                page_flags = ""
                for look_ahead in range(idx + 2, min(idx + 14, len(lines))):
                    if _VTOP_HEADER_RE.match(lines[look_ahead]):
                        break
                    if "PAGE" in lines[look_ahead] and "PHYSICAL" in lines[look_ahead]:
                        if look_ahead + 1 < len(lines):
                            pm = _VTOP_PAGE_ROW_RE.match(lines[look_ahead + 1])
                            if pm:
                                page_struct = int(pm.group("page"), 16)
                                page_phys_base = int(pm.group("phys_base"), 16)
                                page_flags = pm.group("flags").strip()
                        break
                key = (vaddr, paddr)
                if key not in seen:
                    seen.add(key)
                    results.append(
                        VtopTranslation(
                            virtual_address=vaddr,
                            physical_address=paddr,
                            page_offset=vaddr & 0xFFF,
                            linear_map_delta=vaddr - paddr,
                            page_struct_address=page_struct,
                            page_physical_base=page_phys_base,
                            page_flags=page_flags,
                        )
                    )
                idx += 2
                continue
        idx += 1

    return results


def coalesce_memory_reads(reads: Iterable[MemoryRead]) -> list[MemoryRead]:
    """Merge contiguous or overlapping reads into blocks.

    Duck-typed on ``address``/``words`` so that instances produced by a
    previously imported module copy (e.g. after a module reload in tests)
    are not silently dropped by an ``isinstance`` check.
    """

    word_map: dict[int, int] = {}
    for read in reads:
        address = getattr(read, "address", None)
        words = getattr(read, "words", None)
        if not isinstance(address, int) or not words:
            continue
        for index, word in enumerate(words):
            word_map[address + index * _WORD_SIZE] = word

    if not word_map:
        return []

    ordered_addrs = sorted(word_map)
    merged: list[MemoryRead] = []
    block_start = ordered_addrs[0]
    block_words = [word_map[block_start]]
    prev_addr = block_start

    for addr in ordered_addrs[1:]:
        if addr == prev_addr + _WORD_SIZE:
            block_words.append(word_map[addr])
        else:
            merged.append(MemoryRead(address=block_start, words=tuple(block_words)))
            block_start = addr
            block_words = [word_map[addr]]
        prev_addr = addr

    merged.append(MemoryRead(address=block_start, words=tuple(block_words)))
    return merged


def _is_trivial_word(word: int) -> bool:
    if word in (0, 0xFFFFFFFFFFFFFFFF, 0xDEAD000000000100, 0xDEAD000000000122):
        return True
    low_byte = word & 0xFF
    repeated = 0
    for shift in range(0, 64, 8):
        repeated |= low_byte << shift
    return word == repeated


def detect_memory_block_correlations(
    reads: Iterable[MemoryRead], *, default_stride: int = 128
) -> list[MemoryBlockCorrelation]:
    blocks = coalesce_memory_reads(reads)
    if len(blocks) < 2:
        return []

    correlations: list[MemoryBlockCorrelation] = []
    seen_pairs: set[tuple[int, int]] = set()

    for i in range(len(blocks)):
        for j in range(i + 1, len(blocks)):
            low_block, high_block = blocks[i], blocks[j]
            if low_block.address > high_block.address:
                low_block, high_block = high_block, low_block

            high_index_by_word: dict[int, list[int]] = {}
            for h_idx, word in enumerate(high_block.words):
                if not _is_trivial_word(word):
                    high_index_by_word.setdefault(word, []).append(h_idx)

            visited_alignments: set[int] = set()
            for l_idx, word in enumerate(low_block.words):
                if _is_trivial_word(word):
                    continue
                for h_idx in high_index_by_word.get(word, ()): 
                    delta_words = h_idx - l_idx
                    if delta_words in visited_alignments:
                        continue
                    visited_alignments.add(delta_words)

                    start_l = l_idx
                    start_h = h_idx
                    while (
                        start_l > 0
                        and start_h > 0
                        and low_block.words[start_l - 1] == high_block.words[start_h - 1]
                    ):
                        start_l -= 1
                        start_h -= 1

                    end_l = l_idx
                    end_h = h_idx
                    while (
                        end_l + 1 < len(low_block.words)
                        and end_h + 1 < len(high_block.words)
                        and low_block.words[end_l + 1] == high_block.words[end_h + 1]
                    ):
                        end_l += 1
                        end_h += 1

                    matching_words = end_l - start_l + 1
                    if matching_words < 4:
                        continue

                    non_trivial_values = {
                        low_block.words[k]
                        for k in range(start_l, end_l + 1)
                        if not _is_trivial_word(low_block.words[k])
                    }
                    if len(non_trivial_values) < 2:
                        continue

                    low_start_addr = low_block.address + start_l * _WORD_SIZE
                    high_start_addr = high_block.address + start_h * _WORD_SIZE
                    pair_key = (low_start_addr, high_start_addr)
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)

                    exact_bytes = matching_words * _WORD_SIZE
                    first_diff_offset: int | None = None
                    low_diff_word: int | None = None
                    high_diff_word: int | None = None

                    if (
                        end_l + 1 < len(low_block.words)
                        and end_h + 1 < len(high_block.words)
                    ):
                        next_low = low_block.words[end_l + 1]
                        next_high = high_block.words[end_h + 1]
                        low_diff_word = next_low
                        high_diff_word = next_high
                        low_bytes = (next_low & ((1 << 64) - 1)).to_bytes(8, "little")
                        high_bytes = (next_high & ((1 << 64) - 1)).to_bytes(8, "little")
                        prefix_match = 0
                        for b_low, b_high in zip(low_bytes, high_bytes):
                            if b_low == b_high:
                                prefix_match += 1
                            else:
                                break
                        exact_bytes += prefix_match
                        first_diff_offset = exact_bytes

                    stride = default_stride if default_stride > 0 else 128
                    spanned_slots = max(1, (exact_bytes + stride - 1) // stride)
                    correlations.append(
                        MemoryBlockCorrelation(
                            low_address=low_start_addr,
                            high_address=high_start_addr,
                            address_delta=high_start_addr - low_start_addr,
                            matching_words=matching_words,
                            exact_match_bytes=exact_bytes,
                            first_diff_offset=first_diff_offset,
                            low_diff_word=low_diff_word,
                            high_diff_word=high_diff_word,
                            stride=stride,
                            spanned_slots=spanned_slots,
                        )
                    )

    correlations.sort(
        key=lambda item: (-item.exact_match_bytes, item.low_address, item.high_address)
    )
    return correlations


def format_mechanical_analysis_summary(
    current_output: str,
    all_memory_reads: Iterable[MemoryRead] = (),
    *,
    default_stride: int = 128,
    correlations: list[MemoryBlockCorrelation] | None = None,
) -> str:
    if not isinstance(current_output, str) or not current_output.strip():
        return ""

    lines: list[str] = []

    slab_infos = parse_kmem_slab_outputs(current_output)
    for info in slab_infos[:6]:
        adj_parts: list[str] = []
        if info.prev_slot is not None:
            adj_parts.append(f"prev_slot=0x{info.prev_slot:x}")
        if info.next_slot is not None:
            adj_parts.append(f"next_slot=0x{info.next_slot:x}")
        adj_str = f" ({', '.join(adj_parts)})" if adj_parts else ""
        lines.append(
            f"- slab_slot: 0x{info.slot_address:x}..0x{info.slot_end:x} "
            f"cache={info.cache_name} objsize={info.obj_size}B "
            f"state={info.allocation_state.upper()} "
            f"slab_base=0x{info.slab_memory_base:x} "
            f"slot_index={info.slot_index}/{info.total_objects} "
            f"(offset=+0x{info.slot_offset_in_slab:x}){adj_str}"
        )

    vtop_infos = parse_vtop_outputs(current_output)
    for vt in vtop_infos[:6]:
        page_str = (
            f" page_struct=0x{vt.page_struct_address:x} page_phys=0x{vt.page_physical_base:x}"
            if vt.page_struct_address is not None and vt.page_physical_base is not None
            else ""
        )
        flags_str = f" flags=[{vt.page_flags}]" if vt.page_flags else ""
        lines.append(
            f"- vtop_map: vaddr=0x{vt.virtual_address:x} -> paddr=0x{vt.physical_address:x} "
            f"(page_offset=+0x{vt.page_offset:x}, vaddr_minus_paddr=0x{vt.linear_map_delta:x})"
            f"{page_str}{flags_str}"
        )

    current_reads = parse_memory_reads(current_output)
    if current_reads:
        current_block_addrs = {
            read.address + idx * _WORD_SIZE
            for read in current_reads
            for idx in range(len(read.words))
        }
        combined_reads = list(all_memory_reads) if all_memory_reads else current_reads
        candidates = (
            list(correlations)
            if correlations is not None
            else detect_memory_block_correlations(
                combined_reads, default_stride=default_stride
            )
        )
        emitted = 0
        for corr in candidates:
            if emitted >= 4:
                break
            low_range = {corr.low_address + k * _WORD_SIZE for k in range(corr.matching_words)}
            high_range = {corr.high_address + k * _WORD_SIZE for k in range(corr.matching_words)}
            if not (((low_range | high_range) & current_block_addrs)):
                continue
            emitted += 1
            diff_str = (
                f", first_diff_at=+0x{corr.first_diff_offset:x} "
                f"(low_word=0x{corr.low_diff_word:016x} vs high_word=0x{corr.high_diff_word:016x})"
                if corr.first_diff_offset is not None
                and corr.low_diff_word is not None
                and corr.high_diff_word is not None
                else ""
            )
            lines.append(
                f"- memory_copy_candidate: 0x{corr.low_address:x} <-> 0x{corr.high_address:x} "
                f"const_addr_delta=+0x{corr.address_delta:x} "
                f"identical_prefix={corr.exact_match_bytes}B (0x{corr.exact_match_bytes:x}, "
                f"{corr.matching_words} qwords, spans {corr.spanned_slots}x{corr.stride}B slots)"
                f"{diff_str} "
                f"[候选关联，需协议解码确认]"
            )

    if not lines:
        return ""
    return "[mechanical-analysis]\n" + "\n".join(lines)
