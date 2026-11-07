#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# model.py - LLM 模型配置和初始化模块
# Author: CalmWU
# Created: 2026-01-09

import os
from typing import Any
from pydantic import SecretStr

from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage
from src.utils.logging import logger
from src.utils.settings import get_settings
from langchain_deepseek.chat_models import ChatDeepSeek


class ChatDeepSeekReasoner(ChatDeepSeek):
    """ChatDeepSeek 子类，修复 reasoning_content 在多轮对话中丢失的问题。

    langchain-deepseek 在接收响应时会将 reasoning_content 存入
    AIMessage.additional_kwargs，但在发送请求时 _convert_message_to_dict
    不会将其写回序列化后的消息字典。DeepSeek-Reasoner API 要求多轮对话中
    每条 assistant 消息都必须包含 reasoning_content 字段，否则返回 400 错误。
    """

    def _get_request_payload(
        self,
        input_: Any,
        *,
        stop: list[str] | None = None,
        **kwargs: Any,
    ) -> dict:
        # 在序列化前获取原始 BaseMessage 列表
        messages = self._convert_input(input_).to_messages()
        payload = super()._get_request_payload(input_, stop=stop, **kwargs)

        # 将 reasoning_content 注入到序列化后的 assistant 消息中
        if "messages" in payload:
            ai_msg_index = 0
            for orig_msg in messages:
                if isinstance(orig_msg, AIMessage):
                    reasoning = orig_msg.additional_kwargs.get("reasoning_content")
                    # 在 payload["messages"] 中找到对应的 assistant 消息
                    while ai_msg_index < len(payload["messages"]):
                        if payload["messages"][ai_msg_index].get("role") == "assistant":
                            if reasoning is not None:
                                payload["messages"][ai_msg_index][
                                    "reasoning_content"
                                ] = reasoning
                            ai_msg_index += 1
                            break
                        ai_msg_index += 1

        return payload


def create_reasoning_llm():
    """Create and return the reasoning LLM instance."""
    settings = get_settings()
    api_key = settings.reasoning_api_key
    base_url = settings.reasoning_base_url
    thinking = settings.reasoning_thinking
    model_name = settings.reasoning_model
    temperature = settings.reasoning_temperature
    reasoning_effort = settings.reasoning_effort
    max_tokens = settings.reasoning_max_output_tokens

    # 配置 LangSmith 追踪
    if settings.langsmith_tracing:
        os.environ["LANGSMITH_TRACING"] = "true"

    # top_p 值      采样集合大小    随机性        确定性        适合场景
    # top_p=0.1     很小           很低          很高          代码生成、事实回答
    # top_p=0.5     中等           中等          中等          创意写作、头脑风暴
    # top_p=0.9     较大           较高          较低          探索性分析、多样化输出
    # top_p=1.0     全部词汇       最高          最低          开放式创作

    try:
        if settings.sends_thinking_field:
            # deepseek 档位（DeepSeek 官方 / 阿里云 compatible-mode）：
            # 使用 ChatDeepSeek 系列并显式下发私有 thinking 字段；
            # ChatDeepSeek 用 api_base 字段构建真实客户端，传 base_url 不会生效。
            endpoint_kwargs = {"api_base": base_url}
            if thinking == "enabled":
                llm_class = ChatDeepSeekReasoner
                llm_kwargs = {
                    "reasoning_effort": reasoning_effort,
                    "extra_body": {"thinking": {"type": "enabled"}},
                }
            else:
                llm_class = ChatDeepSeek
                llm_kwargs = {
                    "top_p": 0.1,
                    "presence_penalty": 0,
                    "temperature": temperature,
                    "extra_body": {"thinking": {"type": "disabled"}},
                }
        else:
            # openai 档位（严格校验 /v1/chat/completions 的网关，如 AMD developer 网关）：
            # 使用标准 ChatOpenAI（base_url），绝不注入未知顶层参数 thinking。
            llm_class = ChatOpenAI
            endpoint_kwargs = {"base_url": base_url}
            if thinking == "enabled":
                llm_kwargs = {
                    "reasoning_effort": reasoning_effort,
                }
            else:
                llm_kwargs = {
                    "top_p": 0.1,
                    "presence_penalty": 0,
                    "temperature": temperature,
                }

        llm = llm_class(
            api_key=SecretStr(str(api_key)),
            model=model_name,
            max_tokens=max_tokens,
            timeout=300,  # 5 分钟超时，后期步骤对话历史很长，LLM 推理耗时较久
            max_retries=3,  # 遇到连接超时等瞬态错误时自动重试
            **endpoint_kwargs,
            **llm_kwargs,
        )
        logger.info(
            "Successfully created LLM instance (profile=%s): %s",
            settings.reasoning_param_profile,
            llm,
        )
        return llm
    except Exception as e:
        logger.error(f"Failed to create LLM instance: {e}")
        raise


