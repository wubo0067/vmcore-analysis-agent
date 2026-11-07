
#!/usr/bin/env bash
#
# get-kernel-source.sh
#
# Kernel SRPM source preparation tool
#
# Features:
#   1. Download Kernel SRPM by kernel version
#   2. Use local SRPM
#   3. Automatically detect RHEL 7/8/9/10
#   4. Enable available Source RPM repositories
#   5. Isolated workspace for each kernel version
#   6. Install SRPM into independent workspace
#   7. Validate SRPM using SHA256
#   8. Run rpmbuild -bp
#   9. Locate prepared kernel source directory
#  10. Support repeated execution
#  11. Support skipping preparation
#  12. Support workspace cleanup
#  13. stdout only returns prepared source directory
#
# ============================================================

set -Eeuo pipefail

SCRIPT_NAME=$(basename "$0")

SOURCE_ROOT="${SOURCE_ROOT:-/root/kernel-sources}"
SKIP_PREPARE="${SKIP_PREPARE:-0}"

HOST_ARCH=$(uname -m)

SUPPORTED_RHEL_VERSIONS=(7 8 9 10)

KERNEL_VERSION=""
KERNEL_NEVR=""
RHEL_MAJOR=""
SRPM=""
UNINSTALL=0

WORK_DIR=""
TOPDIR=""
BUILD_DIR=""
BUILDROOT_DIR=""
RPMS_DIR=""
SOURCES_DIR=""
SPECS_DIR=""
SRPMS_DIR=""
SPEC_FILE=""
PREPARED_SOURCE_DIR=""

# ============================================================
# 1. Logging
# ============================================================

log()
{
    echo "[$(date '+%F %T')] [INFO] $*" >&2
}

warn()
{
    echo "[$(date '+%F %T')] [WARN] $*" >&2
}

error()
{
    echo "[$(date '+%F %T')] [ERROR] $*" >&2
}

die()
{
    error "$*"
    exit 1
}

# ============================================================
# 2. Usage
# ============================================================

usage()
{
    cat >&2 <<EOF

Usage:
  $SCRIPT_NAME [OPTIONS] KERNEL_VERSION
  $SCRIPT_NAME --srpm FILE
  $SCRIPT_NAME --uninstall KERNEL_VERSION
  $SCRIPT_NAME --uninstall --srpm FILE

Options:

  --srpm FILE, -s FILE
      Use an existing local Kernel SRPM.

  --uninstall
      Remove the workspace of the specified kernel version.

  --usage, --help, -h
      Display usage information.

Environment:

  SOURCE_ROOT=/root/kernel-sources
      Kernel source workspace root.

  SKIP_PREPARE=1
      Skip download, installation and preparation.

Examples:

  $SCRIPT_NAME 4.18.0-305.130.1.el8_4.x86_64

  $SCRIPT_NAME --srpm /root/SRPMS/kernel-4.18.0-305.130.1.el8_4.src.rpm

  SKIP_PREPARE=1 $SCRIPT_NAME 4.18.0-305.130.1.el8_4.x86_64

  $SCRIPT_NAME --uninstall 4.18.0-305.130.1.el8_4.x86_64

EOF
}

# ============================================================
# 3. Argument parsing
# ============================================================

while [[ $# -gt 0 ]]; do

    case "$1" in

        --srpm|-s)

            [[ $# -ge 2 ]] || die "$1 requires a file path"

            [[ -n "$2" && "$2" != -* ]] ||
                die "Invalid SRPM file path"

            SRPM="$2"
            shift 2
            ;;

        --srpm=*)

            SRPM="${1#*=}"

            [[ -n "$SRPM" ]] ||
                die "--srpm requires a file path"

            shift
            ;;

        --uninstall)

            UNINSTALL=1
            shift
            ;;

        --usage|--help|-h)

            usage
            exit 0
            ;;

        -*)

            die "Unknown option: $1"
            ;;

        *)

            [[ -z "$KERNEL_VERSION" ]] ||
                die "Multiple kernel versions specified"

            KERNEL_VERSION="$1"
            shift
            ;;

    esac

done

# ============================================================
# 4. Dependency checks
# ============================================================

check_command()
{
    command -v "$1" >/dev/null 2>&1 ||
        die "Required command not found: $1"
}

check_basic_dependencies()
{
    check_command rpm
    check_command uname
    check_command readlink
    check_command mkdir
}

check_build_dependencies()
{
    local required=(
        rpmbuild
        find
        cp
        rm
        patch
        tar
        xz
        gzip
        bzip2
    )

    local missing=()
    local cmd

    for cmd in "${required[@]}"; do

        command -v "$cmd" >/dev/null 2>&1 ||
            missing+=("$cmd")

    done

    if ((${#missing[@]})); then

        die "Missing build dependencies: ${missing[*]}"

    fi

    local optional=(
        make
        gcc
        perl
        python3
        pathfix.py
    )

    local absent=()

    for cmd in "${optional[@]}"; do

        command -v "$cmd" >/dev/null 2>&1 ||
            absent+=("$cmd")

    done

    if ((${#absent[@]})); then

        warn "Optional commands not found: ${absent[*]}"

    fi
}

# ============================================================
# 5. Normalize kernel version
# ============================================================

normalize_kernel_version()
{
    local input="$1"

    input="${input%.x86_64}"
    input="${input%.aarch64}"
    input="${input%.ppc64le}"
    input="${input%.s390x}"

    [[ "$input" == *-* ]] ||
        die "Invalid kernel version: $input"

    KERNEL_NEVR="$input"

    detect_rhel_major "$KERNEL_NEVR"

    log "Target kernel: $KERNEL_NEVR"
}

# ============================================================
# 6. Detect RHEL major version
# ============================================================

detect_rhel_major()
{
    local version="$1"

    if [[ "$version" =~ \.el([0-9]+)(_|\.|$) ]]; then

        RHEL_MAJOR="${BASH_REMATCH[1]}"

    else

        die "Cannot detect RHEL version from: $version"

    fi

    local supported=0
    local v

    for v in "${SUPPORTED_RHEL_VERSIONS[@]}"; do

        if [[ "$RHEL_MAJOR" == "$v" ]]; then

            supported=1
            break

        fi

    done

    [[ "$supported" -eq 1 ]] ||
        die "Unsupported RHEL major version: $RHEL_MAJOR"

    log "Detected RHEL major version: $RHEL_MAJOR"
}

# ============================================================
# 7. Parse SRPM metadata
# ============================================================

parse_srpm()
{
    [[ -n "$SRPM" ]] || return 0

    [[ -f "$SRPM" ]] ||
        die "SRPM file not found: $SRPM"

    SRPM=$(readlink -f "$SRPM")

    [[ "$SRPM" == *.src.rpm ]] ||
        die "Invalid SRPM file: expected *.src.rpm"

    local name
    local version
    local release

    name=$(rpm -qp --qf '%{NAME}' "$SRPM") ||
        die "Cannot read SRPM package name"

    version=$(rpm -qp --qf '%{VERSION}' "$SRPM") ||
        die "Cannot read SRPM VERSION"

    release=$(rpm -qp --qf '%{RELEASE}' "$SRPM") ||
        die "Cannot read SRPM RELEASE"

    [[ "$name" == "kernel" ]] ||
        die "Invalid SRPM package name: $name"

    KERNEL_NEVR="${version}-${release}"

    if [[ -n "$KERNEL_VERSION" ]]; then

        local input_version="$KERNEL_VERSION"

        input_version="${input_version%.x86_64}"
        input_version="${input_version%.aarch64}"
        input_version="${input_version%.ppc64le}"
        input_version="${input_version%.s390x}"

        [[ "$input_version" == "$KERNEL_NEVR" ]] ||
            die "Specified version does not match SRPM metadata"

    fi

    detect_rhel_major "$KERNEL_NEVR"

    log "Local SRPM: $SRPM"
    log "SRPM package: $name"
    log "SRPM version: $version"
    log "SRPM release: $release"
}

# ============================================================
# 8. Initialize isolated workspace
# ============================================================

setup_workspace()
{
    SOURCE_ROOT=$(mkdir -p "$SOURCE_ROOT" && readlink -f "$SOURCE_ROOT")

    [[ "$SOURCE_ROOT" != "/" ]] ||
        die "SOURCE_ROOT cannot be /"

    WORK_DIR="${SOURCE_ROOT}/${RHEL_MAJOR}/${KERNEL_NEVR}"

    TOPDIR="$WORK_DIR"

    BUILD_DIR="${TOPDIR}/BUILD"
    BUILDROOT_DIR="${TOPDIR}/BUILDROOT"
    RPMS_DIR="${TOPDIR}/RPMS"
    SOURCES_DIR="${TOPDIR}/SOURCES"
    SPECS_DIR="${TOPDIR}/SPECS"
    SRPMS_DIR="${TOPDIR}/SRPMS"

    SPEC_FILE="${SPECS_DIR}/kernel.spec"

    PREPARED_SOURCE_DIR=""

    log "Workspace: $WORK_DIR"
}

# ============================================================
# 9. Remove workspace
# ============================================================

uninstall_workspace()
{
    if [[ ! -d "$WORK_DIR" ]]; then

        log "Workspace does not exist: $WORK_DIR"
        return 0

    fi

    local resolved

    resolved=$(readlink -f "$WORK_DIR") ||
        die "Cannot resolve workspace path"

    [[ "$resolved" == "$SOURCE_ROOT/"* ]] ||
        die "Unsafe workspace path: $resolved"

    [[ "$resolved" != "$SOURCE_ROOT" ]] ||
        die "Refusing to remove SOURCE_ROOT"

    log "Removing workspace: $resolved"

    rm -rf -- "$resolved"

    log "Workspace removed"
}

# ============================================================
# 10. Create workspace
# ============================================================

create_workspace()
{
    mkdir -p \
        "$BUILD_DIR" \
        "$BUILDROOT_DIR" \
        "$RPMS_DIR" \
        "$SOURCES_DIR" \
        "$SPECS_DIR" \
        "$SRPMS_DIR"

    log "Workspace created"
}

# ============================================================
# 11. Enable Source RPM repositories
# ============================================================

enable_source_repositories()
{
    if ! command -v subscription-manager >/dev/null 2>&1; then

        warn "subscription-manager not found"

        return 0

    fi

    log "Checking available Source RPM repositories"

    local repo_list

    repo_list=$(subscription-manager repos --list --available 2>/dev/null || true)

    local repo_ids=()
    local repo

    while IFS= read -r repo; do

        [[ -n "$repo" ]] || continue

        repo_ids+=("$repo")

    done < <(
        printf '%s\n' "$repo_list" |
            awk '/Repo ID:/ {print $3}' |
            grep -E "^rhel-${RHEL_MAJOR}.*source-rpms$" || true
    )

    if ((${#repo_ids[@]} == 0)); then

        warn "No matching Source RPM repository found"

        return 0

    fi

    for repo in "${repo_ids[@]}"; do

        log "Enabling: $repo"

        subscription-manager repos \
            --enable="$repo" >&2 ||
            warn "Failed to enable: $repo"

    done
}

# ============================================================
# 12. Download SRPM
# ============================================================

download_srpm()
{
    mkdir -p "$SRPMS_DIR"

    local package_spec="kernel-${KERNEL_NEVR}"

    log "Downloading: $package_spec"

    if command -v dnf >/dev/null 2>&1; then

        dnf download \
            --source \
            --destdir="$SRPMS_DIR" \
            "$package_spec" >&2 ||
            die "DNF SRPM download failed"

    elif command -v yumdownloader >/dev/null 2>&1; then

        yumdownloader \
            --source \
            --destdir="$SRPMS_DIR" \
            "$package_spec" >&2 ||
            die "YUM SRPM download failed"

    else

        die "Neither dnf nor yumdownloader is available"

    fi

    local file
    local nevr
    local found=""

    while IFS= read -r file; do

        nevr=$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$file" 2>/dev/null) ||
            continue

        if [[ "$nevr" == "$KERNEL_NEVR" ]]; then

            found="$file"
            break

        fi

    done < <(
        find "$SRPMS_DIR" \
            -maxdepth 1 \
            -type f \
            -name 'kernel-*.src.rpm'
    )

    [[ -n "$found" ]] ||
        die "Cannot find downloaded SRPM for $KERNEL_NEVR"

    SRPM=$(readlink -f "$found")

    log "Downloaded SRPM: $SRPM"
}

# ============================================================
# 13. Install SRPM
# ============================================================

install_srpm()
{
    [[ -f "$SRPM" ]] ||
        die "SRPM not found: $SRPM"

    local checksum
    local marker="${TOPDIR}/.srpm.sha256"

    checksum=$(sha256sum "$SRPM" | awk '{print $1}')

    if [[ -f "$SPEC_FILE" && -f "$marker" ]]; then

        local old_checksum

        old_checksum=$(<"$marker")

        if [[ "$checksum" == "$old_checksum" ]]; then

            log "SRPM unchanged, skipping installation"

            return 0

        fi

    fi

    log "SRPM changed or not installed; reinstalling"

    # Remove stale spec and source files.
    find "$SPECS_DIR" \
        -mindepth 1 -maxdepth 1 \
        -exec rm -rf -- {} +

    find "$SOURCES_DIR" \
        -mindepth 1 -maxdepth 1 \
        -exec rm -rf -- {} +

    log "Installing SRPM"

    rpm -ivh \
        --define "_topdir $TOPDIR" \
        --replacepkgs \
        --replacefiles \
        "$SRPM" >&2 ||
        die "SRPM installation failed"

    [[ -f "$SPEC_FILE" ]] ||
        die "kernel.spec not found after SRPM installation"

    printf '%s\n' "$checksum" > "$marker"

    log "SRPM installed successfully"
}

# ============================================================
# 14. Find prepared kernel source
# ============================================================

find_prepared_source()
{
    local config_file
    local source_dir

    [[ -d "$BUILD_DIR" ]] || return 1

    while IFS= read -r config_file; do

        source_dir="${config_file%/init/Kconfig}"

        [[ -f "$source_dir/Makefile" ]] || continue
        [[ -d "$source_dir/kernel" ]] || continue
        [[ -d "$source_dir/arch" ]] || continue
        [[ -d "$source_dir/include" ]] || continue

        printf '%s\n' "$source_dir"

        return 0

    done < <(
        find "$BUILD_DIR" \
            -type f \
            -path '*/init/Kconfig' \
            -print
    )

    return 1
}

# ============================================================
# 15. Run rpmbuild -bp
# ============================================================


prepare_source()
{
    [[ -f "$SPEC_FILE" ]] ||
        die "kernel.spec not found: $SPEC_FILE"

    check_build_dependencies

    log "Host OS:"
    grep -E '^(NAME|VERSION_ID)=' /etc/os-release >&2 || true

    log "Target kernel: $KERNEL_NEVR"
    log "Target RHEL major: $RHEL_MAJOR"
    log "RPM target architecture: $HOST_ARCH"

    # --------------------------------------------------------
    # IMPORTANT:
    # Override host RPM distribution macros.
    #
    # Host:   RHEL 9
    # Target: RHEL 8
    #
    # Do not let the host's .el9 dist macro leak into
    # the target kernel source preparation.
    # --------------------------------------------------------

    local target_dist=".el${RHEL_MAJOR}"

    log "Overriding RPM distribution macros:"
    log "  rhel = $RHEL_MAJOR"
    log "  dist = $target_dist"

    log "Checking kernel.spec metadata"

    rpm -q --specfile "$SPEC_FILE" \
        --qf '%{NAME} %{VERSION}-%{RELEASE}\n' >&2 ||
        die "Cannot parse kernel.spec"

    # --------------------------------------------------------
    # Clean previous BUILD directory
    # --------------------------------------------------------

    if [[ -d "$BUILD_DIR" ]]; then

        find "$BUILD_DIR" \
            -mindepth 1 \
            -maxdepth 1 \
            -exec rm -rf -- {} +

    fi

    # --------------------------------------------------------
    # Prepare source using target distribution macros
    # --------------------------------------------------------

    log "Running rpmbuild -bp with target RHEL macros"

    rpmbuild -bp \
        --define "rhel $RHEL_MAJOR" \
        --define "dist $target_dist" \
        --define "_topdir $TOPDIR" \
        --target="$HOST_ARCH" \
        "$SPEC_FILE" >&2 ||
        die "rpmbuild -bp failed"

    log "rpmbuild -bp completed"

    # --------------------------------------------------------
    # Locate prepared source
    # --------------------------------------------------------

    PREPARED_SOURCE_DIR=$(find_prepared_source) ||
        die "Cannot locate prepared kernel source"

    [[ -n "$PREPARED_SOURCE_DIR" ]] ||
        die "Prepared source directory is empty"

    [[ -d "$PREPARED_SOURCE_DIR" ]] ||
        die "Prepared source directory does not exist"

    PREPARED_SOURCE_DIR=$(readlink -f "$PREPARED_SOURCE_DIR")

    # --------------------------------------------------------
    # Validate target distribution
    # --------------------------------------------------------

    if [[ "$PREPARED_SOURCE_DIR" == *".el9."* &&
          "$RHEL_MAJOR" == "8" ]]; then

        die "Incorrect EL9 source directory generated on EL9 host: $PREPARED_SOURCE_DIR. Check kernel.spec for hardcoded EL9 macros."

    fi

    log "Prepared source: $PREPARED_SOURCE_DIR"
}


# ============================================================
# 16. Skip preparation
# ============================================================

skip_prepare()
{
    log "SKIP_PREPARE=1"

    PREPARED_SOURCE_DIR=$(find_prepared_source) ||
        die "Prepared source does not exist: $BUILD_DIR"

    PREPARED_SOURCE_DIR=$(readlink -f "$PREPARED_SOURCE_DIR")

    [[ -d "$PREPARED_SOURCE_DIR" ]] ||
        die "Prepared source directory does not exist"

    log "Using existing source: $PREPARED_SOURCE_DIR"
}

# ============================================================
# 17. Main
# ============================================================

main()
{
    check_basic_dependencies

    # --------------------------------------------------------
    # Parse input
    # --------------------------------------------------------

    if [[ -n "$SRPM" ]]; then

        parse_srpm

    else

        [[ -n "$KERNEL_VERSION" ]] || {

            usage
            exit 1

        }

        normalize_kernel_version "$KERNEL_VERSION"

    fi

    # --------------------------------------------------------
    # Initialize workspace
    # --------------------------------------------------------

    setup_workspace

    # --------------------------------------------------------
    # Uninstall
    # --------------------------------------------------------

    if [[ "$UNINSTALL" -eq 1 ]]; then

        uninstall_workspace

        return 0

    fi

    # --------------------------------------------------------
    # Skip preparation
    # --------------------------------------------------------

    if [[ "$SKIP_PREPARE" == "1" ]]; then

        skip_prepare

        printf '%s\n' "$PREPARED_SOURCE_DIR"

        return 0

    fi

    # --------------------------------------------------------
    # Create workspace
    # --------------------------------------------------------

    create_workspace

    # --------------------------------------------------------
    # Download or use local SRPM
    # --------------------------------------------------------

    if [[ -z "$SRPM" ]]; then

        enable_source_repositories

        download_srpm

    else

        log "Using local SRPM; download skipped"

    fi

    # --------------------------------------------------------
    # Copy SRPM into isolated workspace
    # --------------------------------------------------------

    local local_srpm="${SRPMS_DIR}/$(basename "$SRPM")"

    if [[ "$(readlink -f "$SRPM")" != "$local_srpm" ]]; then

        cp -f "$SRPM" "$local_srpm"

    fi

    SRPM="$local_srpm"

    # --------------------------------------------------------
    # Install SRPM
    # --------------------------------------------------------

    install_srpm

    # --------------------------------------------------------
    # Prepare source
    # --------------------------------------------------------

    prepare_source

    # --------------------------------------------------------
    # Return source directory
    # --------------------------------------------------------

    [[ -d "$PREPARED_SOURCE_DIR" ]] ||
        die "Prepared source directory does not exist"

    printf '%s\n' "$PREPARED_SOURCE_DIR"
}

main "$@"
