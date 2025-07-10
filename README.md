# Alive and Route Monitor (alarmon)

## これはなに

[deadman](https://github.com/upa/deadman)をRustで実装したTUIベースのネットワーク監視ツールです。

リアルタイムでpingとtracerouteを実行し、ネットワークの到達性と経路情報を監視できます。

## 機能

- リアルタイムpingモニタリング: 複数のターゲットIPアドレスに対する継続的なping監視
- traceroute機能: ネットワーク経路の可視化と分析
- TUIインターフェース: 直感的な端末ベースのユーザーインターフェース
- 設定ファイル対応: TOML形式での柔軟な監視設定
- 非同期処理: 高効率な並列監視処理
- クロスプラットフォーム: Linux、macOS対応

## Getting Started

### Install Prebuild Binary

GitHub Releasesから最新バイナリをダウンロードできます：

- [最新リリース](https://github.com/cffnpwr/alarmon/releases/latest)

### Build from Source

#### Prerequisites

- Rust 1.85.0以上
- [libpcap](https://www.tcpdump.org/)

#### Build

1. Clone the repository

    ```sh
    git clone https://github.com/cffnpwr/alarmon.git
    cd alarmon
    ```

1. Install dependency libraries (optional)

   - use `libpcap` for packet capture
     - Debian/Ubuntu

       ```sh
       sudo apt install libpcap-dev
       ```

     - CentOS/RHEL

       ```sh
       sudo yum install libpcap-devel
       ```

     - MacOS

       ```sh
       brew install libpcap
       ```

     - Windows

       1. Install [Npcap](https://npcap.com/#download).
       2. Download the [Npcap SDK](https://npcap.com/#download).
       3. Add the SDK's `/Lib` or `/Lib/x64` folder to your LIB environment variable.

1. Build the project

    ```sh
    cargo build --release
    ```

## Roadmap

- [x] ICMPの送受信
  - [x] 経路情報の取得(traceroute機能)
- [x] ファイルからの監視対象の読み込み
- [x] 非同期処理
- [x] TUIでの一覧表示
  - [x] ウィンドウサイズ変更の追従
- [ ] GUIの実装
  - [ ] ネイティブアプリ
  - [ ] Webアプリ
- [ ] 監視対象のグループ化
- [ ] ICMP以外のプロトコルの対応
  - [ ] SSH
  - [ ] HTTP
- [ ] eBPFの使用
- [ ] DPDKの使用
