#!/bin/bash
set -euo pipefail

# PRリリースノート収集スクリプト
# 使用方法: ./collect-release-notes.sh [PR番号]

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
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# 使用方法を表示
usage() {
    echo "使用方法: $0 [PR番号]"
    echo ""
    echo "オプション:"
    echo "  PR番号  : GitHubのPR番号（例: 32）"
    echo ""
    echo "例:"
    echo "  $0 32"
    echo ""
    echo "環境変数:"
    echo "  GITHUB_TOKEN  : GitHubのアクセストークン"
}

# PRの情報を取得
get_pr_info() {
    local pr_number="$1"
    
    if [ -z "${GITHUB_TOKEN:-}" ]; then
        log_error "GITHUB_TOKEN環境変数が設定されていません"
        return 1
    fi
    
    log_info "PR #${pr_number} の情報を取得中..."
    
    # gh CLIを使用してPRの情報を取得
    gh pr view "$pr_number" --json title,body,labels,author,createdAt,mergedAt 2>/dev/null || {
        log_error "PR #${pr_number} の情報を取得できませんでした"
        return 1
    }
}

# PRの本文からリリースノートを抽出
extract_release_notes() {
    local pr_body="$1"
    
    # PR本文全体をリリースノートとして使用（空でも問題なし）
    if [ -z "$pr_body" ] || [ "$pr_body" = "null" ]; then
        echo ""
    else
        echo "$pr_body"
    fi
}

# リリースノートをMarkdown形式で整形
format_release_notes() {
    local release_notes="$1"
    local pr_number="$2"
    local pr_title="$3"
    local pr_author="$4"
    local pr_date="$5"
    
    cat << EOF
### PR #${pr_number}: ${pr_title}

**作成者**: ${pr_author}  
**日付**: ${pr_date}

${release_notes}

---

EOF
}

# 既存のリリースノートファイルを読み込み
load_existing_release_notes() {
    local release_notes_file="${PROJECT_ROOT}/release-notes.md"
    
    if [ -f "$release_notes_file" ]; then
        cat "$release_notes_file"
    else
        echo "# リリースノート"
        echo ""
        echo "このファイルには、リリースに含まれるPRのリリースノートが蓄積されます。"
        echo ""
    fi
}

# リリースノートファイルを更新
update_release_notes_file() {
    local new_release_notes="$1"
    local release_notes_file="${PROJECT_ROOT}/release-notes.md"
    
    # 既存のリリースノートを読み込み
    local existing_notes=$(load_existing_release_notes)
    
    # 新しいリリースノートを追加
    {
        echo "$existing_notes"
        echo "$new_release_notes"
    } > "$release_notes_file"
    
    log_success "リリースノートファイルを更新しました: $release_notes_file"
}

# JSONレポートを生成
generate_json_report() {
    local pr_number="$1"
    local pr_info="$2"
    local release_notes="$3"
    
    local pr_title=$(echo "$pr_info" | jq -r '.title')
    local pr_author=$(echo "$pr_info" | jq -r '.author.login')
    local pr_created_at=$(echo "$pr_info" | jq -r '.createdAt')
    local pr_merged_at=$(echo "$pr_info" | jq -r '.mergedAt // empty')
    
    cat << EOF
{
  "pr_number": $pr_number,
  "title": "$pr_title",
  "author": "$pr_author",
  "created_at": "$pr_created_at",
  "merged_at": "$pr_merged_at",
  "release_notes": $(echo "$release_notes" | jq -R -s '.'),
  "extracted_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
}

# リリースノートの品質を検証
validate_release_notes() {
    local release_notes="$1"
    local warnings=()
    
    # 空のセクションをチェック
    if echo "$release_notes" | grep -q "### 新機能\s*-\s*$"; then
        warnings+=("新機能セクションが空です")
    fi
    
    if echo "$release_notes" | grep -q "### 改善\s*-\s*$"; then
        warnings+=("改善セクションが空です")
    fi
    
    if echo "$release_notes" | grep -q "### バグ修正\s*-\s*$"; then
        warnings+=("バグ修正セクションが空です")
    fi
    
    if echo "$release_notes" | grep -q "### 破壊的変更\s*-\s*$"; then
        warnings+=("破壊的変更セクションが空です")
    fi
    
    # 警告があれば表示
    if [ ${#warnings[@]} -gt 0 ]; then
        log_warn "リリースノートの品質に関する警告:"
        for warning in "${warnings[@]}"; do
            echo "  - $warning"
        done
    fi
    
    return 0
}

# 複数のPRからリリースノートを収集
collect_multiple_prs() {
    local pr_numbers="$1"
    
    log_info "複数のPRからリリースノートを収集中..."
    
    local output_file="${PROJECT_ROOT}/collected-release-notes.json"
    echo "[" > "$output_file"
    
    local first=true
    IFS=',' read -ra PR_ARRAY <<< "$pr_numbers"
    
    for pr_number in "${PR_ARRAY[@]}"; do
        # 前後の空白を削除
        pr_number=$(echo "$pr_number" | xargs)
        
        if ! [[ "$pr_number" =~ ^[0-9]+$ ]]; then
            log_warn "無効なPR番号をスキップ: $pr_number"
            continue
        fi
        
        log_info "PR #${pr_number} を処理中..."
        
        local pr_info
        if ! pr_info=$(get_pr_info "$pr_number"); then
            log_warn "PR #${pr_number} の情報を取得できませんでした"
            continue
        fi
        
        local pr_body
        pr_body=$(echo "$pr_info" | jq -r '.body // empty')
        
        if [ -z "$pr_body" ]; then
            log_warn "PR #${pr_number} の本文が空です"
            continue
        fi
        
        local release_notes=$(extract_release_notes "$pr_body")
        
        if [ -z "$release_notes" ]; then
            log_warn "PR #${pr_number} にリリースノートが見つかりません"
            continue
        fi
        
        validate_release_notes "$release_notes"
        
        # JSONレポートに追加
        if [ "$first" = true ]; then
            first=false
        else
            echo "," >> "$output_file"
        fi
        
        generate_json_report "$pr_number" "$pr_info" "$release_notes" >> "$output_file"
    done
    
    echo "]" >> "$output_file"
    
    log_success "複数PRのリリースノート収集完了"
    log_info "レポートファイル: $output_file"
}

# メイン関数
main() {
    if [ $# -eq 0 ]; then
        usage
        return 1
    fi
    
    local pr_input="$1"
    
    cd "${PROJECT_ROOT}"
    
    # 複数のPR番号が指定された場合（カンマ区切り）
    if [[ "$pr_input" == *","* ]]; then
        collect_multiple_prs "$pr_input"
        return 0
    fi
    
    # 単一のPR番号の場合
    local pr_number="$pr_input"
    
    # 引数の検証
    if ! [[ "$pr_number" =~ ^[0-9]+$ ]]; then
        log_error "PR番号は数値である必要があります: $pr_number"
        return 1
    fi
    
    # PRの情報を取得
    local pr_info
    if ! pr_info=$(get_pr_info "$pr_number"); then
        return 1
    fi
    
    local pr_body
    pr_body=$(echo "$pr_info" | jq -r '.body // empty')
    
    if [ -z "$pr_body" ]; then
        log_error "PR #${pr_number} の本文が空です"
        return 1
    fi
    
    # リリースノートを抽出
    local release_notes=$(extract_release_notes "$pr_body")
    
    if [ -z "$release_notes" ]; then
        log_error "PR #${pr_number} にリリースノートが見つかりません"
        return 1
    fi
    
    # リリースノートの品質を検証
    validate_release_notes "$release_notes"
    
    # PRの基本情報を取得
    local pr_title=$(echo "$pr_info" | jq -r '.title')
    local pr_author=$(echo "$pr_info" | jq -r '.author.login')
    local pr_date=$(echo "$pr_info" | jq -r '.createdAt' | cut -d'T' -f1)
    
    # リリースノートを整形
    local formatted_notes=$(format_release_notes "$release_notes" "$pr_number" "$pr_title" "$pr_author" "$pr_date")
    
    # リリースノートファイルを更新
    update_release_notes_file "$formatted_notes"
    
    # JSONレポートを生成
    local json_report=$(generate_json_report "$pr_number" "$pr_info" "$release_notes")
    echo "$json_report" > "${PROJECT_ROOT}/release-notes-${pr_number}.json"
    
    log_success "PR #${pr_number} のリリースノート収集完了"
    
    # 結果を表示
    echo ""
    echo "=== 収集されたリリースノート ==="
    echo "$formatted_notes"
}

# スクリプトが直接実行された場合のみmainを実行
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi