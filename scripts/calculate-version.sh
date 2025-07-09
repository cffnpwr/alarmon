#!/bin/bash
set -euo pipefail

# ラベルベースのバージョン計算スクリプト
# 使用方法: ./calculate-version.sh [PR番号] [クレート名]

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
    echo "使用方法: $0 [PR番号] [クレート名]"
    echo ""
    echo "オプション:"
    echo "  PR番号     : GitHubのPR番号（例: 32）"
    echo "  クレート名  : 対象のクレート名（例: alarmon, pcap, tcpip）"
    echo ""
    echo "例:"
    echo "  $0 32 alarmon"
    echo "  $0 45 pcap"
    echo ""
    echo "環境変数:"
    echo "  GITHUB_TOKEN  : GitHubのアクセストークン"
}

# GitHubからPRのラベルを取得
get_pr_labels() {
    local pr_number="$1"
    
    if [ -z "${GITHUB_TOKEN:-}" ]; then
        log_error "GITHUB_TOKEN環境変数が設定されていません"
        return 1
    fi
    
    local repo_info=$(gh repo view --json owner,name)
    local owner=$(echo "$repo_info" | jq -r '.owner.login')
    local repo=$(echo "$repo_info" | jq -r '.name')
    
    log_info "PR #${pr_number} のラベルを取得中..."
    
    # gh CLIを使用してPRのラベルを取得
    gh pr view "$pr_number" --json labels | jq -r '.labels[].name'
}

# バージョンタイプを決定
determine_version_type() {
    local pr_number="$1"
    
    local labels=$(get_pr_labels "$pr_number")
    
    # ラベルの優先度（高い順）
    if echo "$labels" | grep -q "^major$"; then
        echo "major"
    elif echo "$labels" | grep -q "^minor$"; then
        echo "minor"
    elif echo "$labels" | grep -q "^patch$"; then
        echo "patch"
    else
        log_warn "バージョンラベル（major/minor/patch）が見つかりません"
        log_warn "見つかったラベル: $(echo "$labels" | tr '\n' ', ')"
        echo "patch"  # デフォルトはpatch
    fi
}

# セマンティックバージョンを増加
increment_version() {
    local current_version="$1"
    local version_type="$2"
    
    # バージョンを配列に分割
    IFS='.' read -ra VERSION_PARTS <<< "$current_version"
    
    local major=${VERSION_PARTS[0]:-0}
    local minor=${VERSION_PARTS[1]:-0}
    local patch=${VERSION_PARTS[2]:-0}
    
    case "$version_type" in
        "major")
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        "minor")
            minor=$((minor + 1))
            patch=0
            ;;
        "patch")
            patch=$((patch + 1))
            ;;
        *)
            log_error "無効なバージョンタイプ: $version_type"
            return 1
            ;;
    esac
    
    echo "${major}.${minor}.${patch}"
}

# バージョン比較レポートを読み込み
load_version_comparison() {
    local comparison_file="${PROJECT_ROOT}/version-comparison.json"
    
    if [ ! -f "$comparison_file" ]; then
        log_error "バージョン比較ファイルが見つかりません: $comparison_file"
        log_info "まず scripts/compare-versions.sh を実行してください"
        return 1
    fi
    
    cat "$comparison_file"
}

# 特定のクレートの情報を取得
get_crate_info() {
    local crate_name="$1"
    local comparison_data="$2"
    
    echo "$comparison_data" | jq -r ".[] | select(.crate == \"$crate_name\")"
}

# 新しいバージョンを計算
calculate_new_version() {
    local pr_number="$1"
    local crate_name="$2"
    
    log_info "PR #${pr_number} のクレート '${crate_name}' のバージョンを計算中..."
    
    # バージョン比較データを読み込み
    local comparison_data=$(load_version_comparison)
    local crate_info=$(get_crate_info "$crate_name" "$comparison_data")
    
    if [ -z "$crate_info" ]; then
        log_error "クレート '$crate_name' の情報が見つかりません"
        return 1
    fi
    
    local current_version=$(echo "$crate_info" | jq -r '.current_version')
    local previous_version=$(echo "$crate_info" | jq -r '.previous_version')
    local comparison=$(echo "$crate_info" | jq -r '.comparison')
    local needs_update=$(echo "$crate_info" | jq -r '.needs_update')
    local dependency_change=$(echo "$crate_info" | jq -r '.dependency_change')
    
    echo ""
    echo "=== バージョン計算結果 ==="
    echo "クレート: $crate_name"
    echo "現在のバージョン: $current_version"
    echo "前のバージョン: $previous_version"
    echo "比較結果: $comparison"
    
    if [ "$comparison" = "different" ]; then
        log_success "バージョンが手動で更新されています"
        log_info "新しいバージョン: $current_version"
        echo "$current_version"
        return 0
    fi
    
    # 依存関係の変更をチェック
    if [ "$dependency_change" = "changed" ]; then
        log_info "依存関係が変更されているため、minorバージョンアップを適用します"
        local new_version=$(increment_version "$previous_version" "minor")
        log_info "計算された新しいバージョン: $new_version"
        echo "$new_version"
        return 0
    fi
    
    # ラベルに基づいてバージョンを計算
    local version_type=$(determine_version_type "$pr_number")
    local new_version=$(increment_version "$previous_version" "$version_type")
    
    log_info "バージョンタイプ: $version_type"
    log_info "計算された新しいバージョン: $new_version"
    
    echo "$new_version"
}

# JSONレポートを生成
generate_version_report() {
    local pr_number="$1"
    local crate_name="$2"
    local current_version="$3"
    local new_version="$4"
    local version_type="$5"
    local was_manual="${6:-false}"
    
    cat << EOF
{
  "pr_number": $pr_number,
  "crate": "$crate_name",
  "current_version": "$current_version",
  "new_version": "$new_version",
  "version_type": "$version_type",
  "was_manual": $was_manual,
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
}

# 全クレートのバージョンを計算
calculate_all_versions() {
    local pr_number="$1"
    
    log_info "全クレートのバージョンを計算中..."
    
    local comparison_data=$(load_version_comparison)
    local output_file="${PROJECT_ROOT}/version-calculation.json"
    
    echo "[" > "$output_file"
    local first=true
    
    while IFS= read -r crate_name; do
        local crate_info=$(get_crate_info "$crate_name" "$comparison_data")
        local current_version=$(echo "$crate_info" | jq -r '.current_version')
        local comparison=$(echo "$crate_info" | jq -r '.comparison')
        
        local new_version
        local version_type
        local was_manual
        
        if [ "$comparison" = "different" ]; then
            new_version="$current_version"
            version_type="manual"
            was_manual=true
        else
            local previous_version=$(echo "$crate_info" | jq -r '.previous_version')
            local dependency_change=$(echo "$crate_info" | jq -r '.dependency_change')
            
            if [ "$dependency_change" = "changed" ]; then
                version_type="minor"
                new_version=$(increment_version "$previous_version" "minor")
            else
                version_type=$(determine_version_type "$pr_number")
                new_version=$(increment_version "$previous_version" "$version_type")
            fi
            was_manual=false
        fi
        
        # JSONレポートに追加
        if [ "$first" = true ]; then
            first=false
        else
            echo "," >> "$output_file"
        fi
        
        generate_version_report "$pr_number" "$crate_name" "$current_version" "$new_version" "$version_type" "$was_manual" >> "$output_file"
        
    done < <(echo "$comparison_data" | jq -r '.[].crate')
    
    echo "]" >> "$output_file"
    
    log_success "全クレートのバージョン計算完了"
    log_info "レポートファイル: $output_file"
    
    # サマリーを表示
    echo ""
    echo "=== バージョン計算サマリー ==="
    jq -r '.[] | "[\(.crate)] \(.current_version) -> \(.new_version) (\(.version_type))"' "$output_file"
}

# メイン関数
main() {
    if [ $# -eq 0 ]; then
        usage
        return 1
    fi
    
    local pr_number="$1"
    local crate_name="${2:-}"
    
    cd "${PROJECT_ROOT}"
    
    # 引数の検証
    if ! [[ "$pr_number" =~ ^[0-9]+$ ]]; then
        log_error "PR番号は数値である必要があります: $pr_number"
        return 1
    fi
    
    if [ -n "$crate_name" ]; then
        # 特定のクレートのバージョンを計算
        calculate_new_version "$pr_number" "$crate_name"
    else
        # 全クレートのバージョンを計算
        calculate_all_versions "$pr_number"
    fi
}

# スクリプトが直接実行された場合のみmainを実行
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi