#!/bin/bash
set -euo pipefail

# ワークスペース各クレートのバージョン比較スクリプト
# 使用方法: ./compare-versions.sh

# 作業ディレクトリを設定
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# 色の定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ログ関数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ワークスペースのクレートリストを取得
get_workspace_crates() {
    cd "${PROJECT_ROOT}"
    
    # メインクレート
    echo "alarmon"
    
    # ワークスペースメンバーを取得
    cargo metadata --format-version=1 --no-deps | \
        jq -r '.workspace_members[]' | \
        sed 's/.*\///' | \
        sed 's/ .*//' | \
        grep -v "^alarmon$" || true
}

# 現在のバージョンを取得
get_current_version() {
    local crate_name="$1"
    cd "${PROJECT_ROOT}"
    
    if [ "$crate_name" = "alarmon" ]; then
        # メインクレートのバージョン
        cargo metadata --format-version=1 --no-deps | \
            jq -r '.packages[] | select(.name == "alarmon") | .version'
    else
        # ワークスペースメンバーのバージョン
        cargo metadata --format-version=1 --no-deps | \
            jq -r ".packages[] | select(.name == \"$crate_name\") | .version"
    fi
}

# 前のバージョンを取得（最新のGitタグから）
get_previous_version() {
    local crate_name="$1"
    cd "${PROJECT_ROOT}"
    
    # タグのパターン: alarmon-v1.0.0, pcap-v0.2.0, tcpip-v0.1.5
    local tag_pattern="${crate_name}-v*"
    
    # 最新のタグを取得
    local latest_tag=$(git tag -l "$tag_pattern" --sort=-version:refname | head -n1)
    
    if [ -z "$latest_tag" ]; then
        echo "0.0.0"
    else
        # タグからバージョンを抽出 (例: alarmon-v1.0.0 -> 1.0.0)
        echo "$latest_tag" | sed "s/^${crate_name}-v//"
    fi
}

# バージョンを比較
compare_versions() {
    local current="$1"
    local previous="$2"
    
    if [ "$current" = "$previous" ]; then
        echo "same"
    else
        echo "different"
    fi
}

# 依存関係の変更を検出
check_dependency_changes() {
    local crate_name="$1"
    cd "${PROJECT_ROOT}"
    
    # 現在のCargo.tomlから依存関係を取得
    local current_deps_file="/tmp/current_deps_${crate_name}.json"
    local previous_deps_file="/tmp/previous_deps_${crate_name}.json"
    
    # 現在の依存関係を取得
    if [ "$crate_name" = "alarmon" ]; then
        cargo metadata --format-version=1 --no-deps | \
            jq -r ".packages[] | select(.name == \"$crate_name\") | {dependencies: .dependencies}" > "$current_deps_file"
    else
        cargo metadata --format-version=1 --no-deps | \
            jq -r ".packages[] | select(.name == \"$crate_name\") | {dependencies: .dependencies}" > "$current_deps_file"
    fi
    
    # 前回のタグでの依存関係を取得
    local tag_pattern="${crate_name}-v*"
    local latest_tag=$(git tag -l "$tag_pattern" --sort=-version:refname | head -n1)
    
    if [ -z "$latest_tag" ]; then
        echo "no_previous_tag"
        return 0
    fi
    
    # 前回のタグの状態で依存関係を取得
    git show "${latest_tag}:Cargo.toml" > /tmp/prev_cargo.toml 2>/dev/null || {
        echo "no_previous_cargo"
        return 0
    }
    
    if [ "$crate_name" != "alarmon" ]; then
        git show "${latest_tag}:${crate_name}/Cargo.toml" > /tmp/prev_cargo.toml 2>/dev/null || {
            echo "no_previous_cargo"
            return 0
        }
    fi
    
    # 前回の依存関係を一時的に解析（簡易版）
    local current_deps_hash=$(jq -S '.dependencies' "$current_deps_file" | sha256sum | cut -d' ' -f1)
    local previous_deps_hash=$(grep -A 100 "^\[dependencies\]" /tmp/prev_cargo.toml | grep -B 100 "^\[" | head -n -1 | sha256sum | cut -d' ' -f1)
    
    if [ "$current_deps_hash" != "$previous_deps_hash" ]; then
        echo "changed"
    else
        echo "unchanged"
    fi
    
    # 一時ファイルを削除
    rm -f "$current_deps_file" "$previous_deps_file" /tmp/prev_cargo.toml
}

# semantic versionの比較
version_compare() {
    local ver1="$1"
    local ver2="$2"
    
    # バージョンを配列に分割
    IFS='.' read -ra VER1 <<< "$ver1"
    IFS='.' read -ra VER2 <<< "$ver2"
    
    # 各要素を比較
    for i in {0..2}; do
        local v1=${VER1[i]:-0}
        local v2=${VER2[i]:-0}
        
        if [ "$v1" -gt "$v2" ]; then
            echo "greater"
            return
        elif [ "$v1" -lt "$v2" ]; then
            echo "less"
            return
        fi
    done
    
    echo "equal"
}

# JSONレポートを生成
generate_report() {
    local crate_name="$1"
    local current_version="$2"
    local previous_version="$3"
    local comparison="$4"
    local dependency_change="$5"
    
    cat << EOF
{
  "crate": "$crate_name",
  "current_version": "$current_version",
  "previous_version": "$previous_version",
  "comparison": "$comparison",
  "needs_update": $([ "$comparison" = "same" ] && echo "true" || echo "false"),
  "version_change": "$(version_compare "$current_version" "$previous_version")",
  "dependency_change": "$dependency_change"
}
EOF
}

# メイン関数
main() {
    log_info "ワークスペースのバージョン比較を開始します"
    
    cd "${PROJECT_ROOT}"
    
    # 出力ファイル
    local output_file="${PROJECT_ROOT}/version-comparison.json"
    echo "[" > "$output_file"
    
    local first=true
    
    # 各クレートのバージョンを比較
    while IFS= read -r crate_name; do
        log_info "クレート '$crate_name' の比較を実行中..."
        
        local current_version=$(get_current_version "$crate_name")
        local previous_version=$(get_previous_version "$crate_name")
        local comparison=$(compare_versions "$current_version" "$previous_version")
        local dependency_change=$(check_dependency_changes "$crate_name")
        
        # 結果を表示
        echo ""
        echo "=== $crate_name ==="
        echo "現在のバージョン: $current_version"
        echo "前のバージョン: $previous_version"
        echo "比較結果: $comparison"
        echo "依存関係の変更: $dependency_change"
        
        if [ "$comparison" = "same" ]; then
            if [ "$dependency_change" = "changed" ]; then
                log_warn "バージョンが同じですが、依存関係が変更されています。minorバージョンアップが推奨されます。"
            else
                log_info "バージョンが同じです。ラベルベースでのバージョンアップが必要です。"
            fi
        else
            log_success "バージョンが更新されています。手動設定のバージョンを使用します。"
        fi
        
        # JSONレポートに追加
        if [ "$first" = true ]; then
            first=false
        else
            echo "," >> "$output_file"
        fi
        
        generate_report "$crate_name" "$current_version" "$previous_version" "$comparison" "$dependency_change" >> "$output_file"
        
    done < <(get_workspace_crates)
    
    echo "]" >> "$output_file"
    
    log_success "バージョン比較完了"
    log_info "レポートファイル: $output_file"
    
    # サマリーを表示
    echo ""
    echo "=== サマリー ==="
    jq -r '.[] | "[\(.crate)] \(.current_version) (前: \(.previous_version)) - \(.comparison)"' "$output_file"
}

# スクリプトが直接実行された場合のみmainを実行
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi