/// スパークラインチャートのネットワークエラーマーカー値
pub const ERROR_MARKER: f64 = -1.0;

/// 保持するレイテンシ履歴エントリの最大数
pub const MAX_HISTORY_SIZE: usize = 50;

/// NerdFontシンボルを使用したアイコン定数
pub const SUCCESS_ICON: &str = "\u{2713}"; // ✓
pub const ERROR_ICON: &str = "\u{2717}"; // ✗
pub const TIMEOUT_ICON: &str = "\u{f199f}"; // 󱦟

/// テーブルレイアウト制約（固定列幅）
/// 名前とホスト列は現在コンテンツに基づく動的幅を使用
pub const TABLE_LOSS_COLUMN_WIDTH: u16 = 5; // 長さ - より多くのチャートスペースのため最小化
pub const TABLE_LATENCY_COLUMN_WIDTH: u16 = 7; // 長さ - より多くのチャートスペースのため最小化
pub const TABLE_AVG_COLUMN_WIDTH: u16 = 7; // 長さ - より多くのチャートスペースのため最小化

/// チャート表示の最小幅
pub const MIN_CHART_WIDTH: u16 = 13;

/// レイアウトの高さ
pub const HEADER_HEIGHT: u16 = 1;
pub const PADDING_HEIGHT: u16 = 1;
pub const FOOTER_HEIGHT: u16 = 3;

/// UIテキスト定数
pub const APP_TITLE: &str = "Alarmon - Alive and Route Monitoring Tool";
pub const FOOTER_TEXT_HIDE: &str =
    "Press Ctrl-C to quit | ↑/↓: Navigate | Enter/Space: Hide details";
pub const FOOTER_TEXT_SHOW: &str =
    "Press Ctrl-C to quit | ↑/↓: Navigate | Enter/Space: Show details";
pub const TABLE_HIGHLIGHT_SYMBOL: &str = "► ";
