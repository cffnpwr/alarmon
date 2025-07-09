#!/bin/bash
set -euo pipefail

# バージョン更新とコミット・タグ作成スクリプト
# 使用方法: ./update-versions.sh

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

# 使用方法を表示
usage() {
    echo "使用方法: $0"
    echo ""
    echo "このスクリプトは version-calculation.json に基づいてバージョンを更新し、"
    echo "コミットとタグを作成します。"
    echo ""
    echo "前提条件:"
    echo "  - scripts/compare-versions.sh の実行済み"
    echo "  - scripts/calculate-version.sh の実行済み"
    echo "  - Gitリポジトリがクリーンな状態"
    echo ""
    echo "オプション:"
    echo "  --dry-run    実際の更新を行わず、変更内容のみを表示"
    echo "  --no-commit  バージョン更新のみを行い、コミットは作成しない"
    echo "  --no-tag     タグを作成しない"
}

# バージョン計算結果を読み込み
load_version_calculation() {
    local calculation_file="${PROJECT_ROOT}/version-calculation.json"
    
    if [ ! -f "$calculation_file" ]; then
        log_error "バージョン計算ファイルが見つかりません: $calculation_file"
        log_info "まず scripts/calculate-version.sh を実行してください"
        return 1
    fi
    
    cat "$calculation_file"
}

# ワークスペースのバージョンを更新
update_workspace_version() {
    local new_version="$1"
    local cargo_toml="${PROJECT_ROOT}/Cargo.toml"
    
    log_info "ワークスペースのバージョンを更新中: $new_version"
    
    # Cargo.tomlのバージョンを更新
    sed -i.bak "s/^version = \".*\"/version = \"$new_version\"/" "$cargo_toml"
    
    # バックアップファイルを削除
    rm -f "${cargo_toml}.bak"
    
    log_success "ワークスペースのバージョンを更新しました: $new_version"
}

# Cargo.lockを更新
update_cargo_lock() {
    log_info "Cargo.lockを更新中..."
    
    cd "${PROJECT_ROOT}"
    cargo update --workspace
    
    log_success "Cargo.lockを更新しました"
}

# 変更されたファイルを確認
check_changes() {
    cd "${PROJECT_ROOT}"
    
    local changed_files=$(git diff --name-only)
    
    if [ -z "$changed_files" ]; then
        log_warn "変更されたファイルがありません"
        return 1
    fi
    
    log_info "変更されたファイル:"
    echo "$changed_files" | while read -r file; do
        echo "  - $file"
    done
    
    return 0
}

# コミットメッセージを生成
generate_commit_message() {
    local calculation_data="$1"
    
    local message="chore: bump version"
    
    # 更新されたクレートの情報を追加
    local updated_crates=$(echo "$calculation_data" | jq -r '.[] | select(.current_version != .new_version) | "\(.crate): \(.current_version) -> \(.new_version)"')
    
    if [ -n "$updated_crates" ]; then
        message="${message}\n\n"
        while IFS= read -r crate_info; do
            message="${message}- ${crate_info}\n"
        done <<< "$updated_crates"
    fi
    
    echo -e "$message"
}

# コミットを作成
create_commit() {
    local calculation_data="$1"
    
    cd "${PROJECT_ROOT}"
    
    if ! check_changes; then
        log_warn "コミットする変更がありません"
        return 1
    fi
    
    local commit_message=$(generate_commit_message "$calculation_data")
    
    log_info "コミットを作成中..."
    git add Cargo.toml Cargo.lock
    git commit -m "$commit_message"
    
    local commit_hash=$(git rev-parse HEAD)
    log_success "コミットを作成しました: $commit_hash"
    
    echo "$commit_hash"
}

# タグを作成
create_tags() {
    local calculation_data="$1"
    local commit_hash="$2"
    
    cd "${PROJECT_ROOT}"
    
    log_info "タグを作成中..."
    
    # 更新されたクレートに対してタグを作成
    while IFS= read -r crate_info; do
        local crate_name=$(echo "$crate_info" | jq -r '.crate')
        local new_version=$(echo "$crate_info" | jq -r '.new_version')
        local current_version=$(echo "$crate_info" | jq -r '.current_version')
        
        # バージョンが変更された場合のみタグを作成
        if [ "$current_version" != "$new_version" ]; then
            local tag_name="${crate_name}-v${new_version}"
            
            log_info "タグを作成: $tag_name"
            git tag -a "$tag_name" "$commit_hash" -m "Release $crate_name v$new_version"
            
            log_success "タグを作成しました: $tag_name"
        fi
    done <<< "$(echo "$calculation_data" | jq -c '.[]')"
}

# ドライランモードでの表示
show_dry_run() {
    local calculation_data="$1"
    
    echo ""
    echo "=== ドライランモード ==="
    echo "以下の変更が行われます:"
    echo ""
    
    # ワークスペースのバージョン更新
    local alarmon_info=$(echo "$calculation_data" | jq -r '.[] | select(.crate == "alarmon")')
    if [ -n "$alarmon_info" ]; then
        local new_version=$(echo "$alarmon_info" | jq -r '.new_version')
        local current_version=$(echo "$alarmon_info" | jq -r '.current_version')
        
        if [ "$current_version" != "$new_version" ]; then
            echo "1. ワークスペースバージョン更新:"
            echo "   $current_version -> $new_version"
            echo ""
        fi
    fi
    
    # 各クレートのタグ作成
    echo "2. 作成されるタグ:"
    while IFS= read -r crate_info; do
        local crate_name=$(echo "$crate_info" | jq -r '.crate')
        local new_version=$(echo "$crate_info" | jq -r '.new_version')
        local current_version=$(echo "$crate_info" | jq -r '.current_version')
        
        if [ "$current_version" != "$new_version" ]; then
            echo "   - ${crate_name}-v${new_version}"
        fi
    done <<< "$(echo "$calculation_data" | jq -c '.[]')"
    
    echo ""
    echo "3. コミットメッセージ:"
    echo "$(generate_commit_message "$calculation_data")"
    echo ""
}

# Gitリポジトリの状態を確認
check_git_status() {
    cd "${PROJECT_ROOT}"
    
    if ! git diff --quiet; then
        log_error "Gitリポジトリにコミットされていない変更があります"
        log_info "以下のコマンドで確認してください: git status"
        return 1
    fi
    
    if ! git diff --staged --quiet; then
        log_error "Gitリポジトリにステージされた変更があります"
        log_info "以下のコマンドで確認してください: git status"
        return 1
    fi
    
    log_success "Gitリポジトリがクリーンです"
}

# メイン関数
main() {
    local dry_run=false
    local no_commit=false
    local no_tag=false
    
    # オプションの解析
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                dry_run=true
                shift
                ;;
            --no-commit)
                no_commit=true
                shift
                ;;
            --no-tag)
                no_tag=true
                shift
                ;;
            --help|-h)
                usage
                return 0
                ;;
            *)
                log_error "無効なオプション: $1"
                usage
                return 1
                ;;
        esac
    done
    
    cd "${PROJECT_ROOT}"
    
    # 前提条件の確認
    if ! check_git_status; then
        return 1
    fi
    
    # バージョン計算結果を読み込み
    local calculation_data=$(load_version_calculation)
    
    # ドライランモードの場合
    if [ "$dry_run" = true ]; then
        show_dry_run "$calculation_data"
        return 0
    fi
    
    # ワークスペースのバージョン更新
    local alarmon_info=$(echo "$calculation_data" | jq -r '.[] | select(.crate == "alarmon")')
    if [ -n "$alarmon_info" ]; then
        local new_version=$(echo "$alarmon_info" | jq -r '.new_version')
        local current_version=$(echo "$alarmon_info" | jq -r '.current_version')
        
        if [ "$current_version" != "$new_version" ]; then
            update_workspace_version "$new_version"
            update_cargo_lock
        fi
    fi
    
    # コミットの作成
    if [ "$no_commit" = false ]; then
        local commit_hash=$(create_commit "$calculation_data")
        
        # タグの作成
        if [ "$no_tag" = false ]; then
            create_tags "$calculation_data" "$commit_hash"
        fi
    fi
    
    log_success "バージョン更新プロセスが完了しました"
}

# スクリプトが直接実行された場合のみmainを実行
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi