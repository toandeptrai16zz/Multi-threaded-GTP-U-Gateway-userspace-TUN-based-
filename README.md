# GTP-U Gateway

Gateway chuyển tiếp gói IPv4 giữa giao diện TUN và một peer GTP-U qua UDP.
Mỗi gateway đọc gói từ `tun0`, đóng gói thành GTP-U G-PDU rồi gửi tới peer;
chiều ngược lại, gateway nhận UDP, kiểm tra GTP-U và TEID rồi ghi gói IPv4
đã giải đóng gói vào TUN.

## Sơ đồ thử nghiệm

Ví dụ chạy hai gateway trong hai Linux network namespace trên cùng một PC:

```text
Linux PC

 Namespace nsA                              Namespace nsB
 ┌─────────────────────┐                    ┌─────────────────────┐
 │ tun0                │                    │                tun0 │
 │ 10.9.0.1/24         │                    │         10.9.0.2/24 │
 │       │             │                    │             ▲       │
 │       ▼             │                    │             │       │
 │ GTP-U GW A ─────────┼──── UDP/2152 ──────┼─ GTP-U GW B │       │
 │       │             │                    │             │       │
 │ vethA 10.200.0.1 ──┼────────────────────┼─ 10.200.0.2 vethB  │
 └─────────────────────┘                    └─────────────────────┘
```

## Yêu cầu

- Linux có hỗ trợ TUN (`/dev/net/tun`) và network namespaces.
- Trình biên dịch C++ hỗ trợ C++11, ví dụ `g++`.
- Quyền root hoặc các quyền tương đương `CAP_NET_ADMIN` để tạo TUN và cấu
  hình network namespace.
- Cho phép lưu lượng UDP trên cổng `2152` giữa hai namespace.

## Biên dịch

Chạy từ thư mục gốc của dự án:

```bash
g++ -std=c++11 -Wall -Wextra -O2 \
  gateway/Gateway.cpp gtpu_encap.cpp -o gateway_app
```

## Tạo topology network namespace

Các lệnh sau tạo hai namespace và một cặp veth nối chúng:

```bash
sudo ip netns add nsA
sudo ip netns add nsB

sudo ip link add vethA type veth peer name vethB
sudo ip link set vethA netns nsA
sudo ip link set vethB netns nsB

sudo ip -n nsA link set lo up
sudo ip -n nsB link set lo up
sudo ip -n nsA addr add 10.200.0.1/24 dev vethA
sudo ip -n nsB addr add 10.200.0.2/24 dev vethB
sudo ip -n nsA link set vethA up
sudo ip -n nsB link set vethB up
```

## Chạy hai gateway

Mở hai terminal. Chạy Gateway A:

```bash
sudo ip netns exec nsA ./gateway_app \
  -i tun0 -b 0.0.0.0 -r 10.200.0.2 -t 9999 -p 2152 -v
```

Chạy Gateway B trong terminal còn lại:

```bash
sudo ip netns exec nsB ./gateway_app \
  -i tun0 -b 0.0.0.0 -r 10.200.0.1 -t 9999 -p 2152 -v
```

Mỗi tiến trình tạo giao diện TUN của riêng namespace. Để gán địa chỉ IP và
bật các giao diện TUN, chạy:

```bash
sudo ip -n nsA addr add 10.9.0.1/24 dev tun0
sudo ip -n nsB addr add 10.9.0.2/24 dev tun0
sudo ip -n nsA link set tun0 up
sudo ip -n nsB link set tun0 up
```

Từ namespace A, gửi ping tới địa chỉ TUN của B:

```bash
sudo ip netns exec nsA ping -c 3 10.9.0.2
```

Khi chạy với `-v`, gateway in thông tin gói và thống kê định kỳ. Có thể
quan sát lưu lượng GTP-U trên liên kết veth bằng:

```bash
sudo ip netns exec nsA tcpdump -ni vethA udp port 2152
```

## Tùy chọn dòng lệnh

| Tùy chọn | Mặc định | Mô tả |
| --- | --- | --- |
| `-i ifname` | `tun0` | Tên giao diện TUN cần tạo |
| `-b bind_ip` | `0.0.0.0` | Địa chỉ bind của UDP socket |
| `-r peer_ip` | `10.200.0.2` | Địa chỉ IPv4 của gateway peer |
| `-t teid` | `9999` | TEID gửi đi và TEID chấp nhận khi nhận |
| `-p port` | `2152` | Cổng UDP dùng cho GTP-U |
| `-v` | Tắt | In thông tin gói IPv4 đã xử lý |

Hai gateway phải được cấu hình cùng TEID và cổng UDP. Dừng gateway bằng
`Ctrl+C`.

## Chạy unit test

Unit test cho hàm đóng gói và giải đóng gói không cần root hoặc TUN:

```bash
g++ -std=c++11 -Wall -Wextra -O0 -g \
  -fsanitize=address,undefined \
  test_gtpu/Test_gtpu.cpp gtpu_encap.cpp -o test_gtpu/test_gtpu
./test_gtpu/test_gtpu
```

## Giới hạn

- Chỉ xử lý gói IPv4 và GTP-U G-PDU với header tối thiểu 8 byte.
- Không xử lý IPv6 hoặc các trường mở rộng GTP-U.
- Gateway không tự gán địa chỉ IP hoặc bật giao diện TUN; cần cấu hình
  riêng như hướng dẫn ở trên.
- Đây là chương trình chuyển tiếp thử nghiệm; GTP-U/UDP trong cấu hình này
  không cung cấp mã hóa hay xác thực peer.
