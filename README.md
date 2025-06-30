# Alive and Route Monitor (alarmon)

## これはなに

[deadman](https://github.com/upa/deadman)をRustで実装したものです。

## Getting Started

### Install Prebuild Binary

TBD

### Build from Source

#### Prequisites

- Rust 1.70.0以上

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
  - [ ] 経路情報の取得(traceroute機能)
- [ ] ファイルからの監視対象の読み込み
- [ ] 非同期処理
- [ ] CLIでの一覧表示
  - [ ] ウィンドウサイズ変更の追従
- [ ] GUIの実装
  - [ ] ネイティブアプリ
  - [ ] Webアプリ
- [ ] 監視対象のグループ化
- [ ] ICMP以外のプロトコルの対応
  - [ ] SSH
  - [ ] HTTP
- [ ] eBPFの使用
- [ ] DPDKの使用
