# MemLabs Lab 0 - Never Too Late Mister
## I. Mô tả thử thách:
- John – là một "nhà hoạt động vì môi trường" và là một người nhân đạo. Anh ta ghét hệ tư tưởng của Thanos trong phim Avengers: Infinity War.
John lập trình rất tệ – anh ta dùng quá nhiều biến trong chương trình của mình.
Một ngày nọ, John đưa cho mình một bản memory dump và nhờ mình tìm hiểu xem anh ta đã làm gì khi chụp bộ nhớ. Bạn có thể tìm ra điều đó giúp mình không?

File thử thách: (được cung cấp qua Google Drive)

Challenge file: [Google Drive](https://drive.google.com/file/d/1MjMGRiPzweCOdikO3DTaVfbdBK5kyynT/view)

🔍 Những manh mối có thể rút ra từ phần mô tả:

- Nhà hoạt động vì môi trường" – có dấu ngoặc kép => có thể là một ám chỉ quan trọng.
- John ghét Thanos – nghe có vẻ vô dụng, nhưng biết đâu sẽ cần.
- John lập trình rất tệ và sử dụng quá nhiều biến – điều này có thể liên quan đến cách viết script hoặc chương trình mà anh ấy đã chạy trong RAM.

## II. Memory Dump Analysis
1. Xác định profile của file **Challenge.raw**:
- Việc đầu tiên khi forensic analysis một **memory dump** là xác định **profile**.
- Profile cho chúng ta biết hệ điều hành của hệ thống hoặc máy tính từ **memory dump**. Volatility (tool) có một **plugin** tích hợp để giúp chúng ta xác định profile của **memory dump**:
- Sử dụng plugin `imaginfo`:
```sh
$ python2 vol.py -f Challenge.raw imageinfo
```
![img](https://github.com/Thuanle2401/CTF/blob/main/ForensisMemLabs/Lab0/lab0.1.png?raw=true)

2. Phân tích hệ thống mục tiêu thông qua **memory dump** từ file **Challenge.raw**:

**Một trong những điều quan trọng nhất mà chúng ta cần biết từ một hệ thống trong quá trình phân tích là:**
- Các tiến trình hoạt động
- Các commands được thực thi trong shell / terminal / Command prompt
- Tiến trình ẩn (nếu có) hoặc tiến trình đã thoát
- Lịch sử trình duyệt (Điều này phụ thuộc rất nhiều đối với tình huống liên quan)

**Bây giờ, để liệt kê các quy trình đang hoạt động hoặc đang chạy, chúng ta sử dụng sự trợ giúp của plugin `pslist`:**

```sh
$ python2 vol.py -f Challenge.raw --profile=Win7SP1x86 pslist
```
![img](https://github.com/Thuanle2401/CTF/blob/main/ForensisMemLabs/Lab0/Lab0.2.png?raw=true)

- Thực hiện lệnh này cung cấp cho chúng ta một danh sách các quá trình đang chạy khi **memory dump** được thực hiện. Đầu ra của lệnh cung cấp các thông tin gồm tên, PID, PPID, Luồng, Xử lý, thời gian bắt đầu, v.v.

**Quan sát kỹ, chúng tôi nhận thấy một số tiến trình cần chú ý:**
- **cmd.exe**
- **DumpIt.exe**
- **explorer.exe**

![img](https://github.com/Thuanle2401/CTF/blob/main/ForensisMemLabs/Lab0/lab0.3.png?raw=true)

- **cmd.exe**: Đây là tiến trình chịu trách nhiệm cho command prompt. Việc trích xuất nội dung từ tiến trình này có thể cung cấp cho chúng ta thông tin chi tiết về những lệnh đã được thực thi trong hệ thống.
- **DumpIt.exe**: Tiến trình này đã được ta sử dụng để có kết xuất được bộ nhớ của hệ thống.
- **Explorer.exe**: Tiến trình này xử lý File Explorer.

**Ta đã thấy rằng cmd.exe đang chạy, hãy thử xem liệu có bất kỳ lệnh nào được thực thi và nội dung được in ra trong shell/terminal hay không.**
- Đối với điều này, ta sử dụng plugin `consoles`

```sh
$ python2 vol.py -f Challenge.raw --profile=Win7SP1x86 consoles
```
![img](https://github.com/Thuanle2401/CTF/blob/main/ForensisMemLabs/Lab0/lab0.4.png?raw=true)

- Từ hình trên, một tệp python đã được thực thi. Lệnh được thực hiện là C:\Python27\python.exe C:\Users\hello\Desktop\demon.py.txt và nội dung trả về là một chuỗi nhất định đã được viết ra stdout. Bây giờ ta có thể thấy đây là một chuỗi được mã hóa hex `335d366f5d6031767631707f`. Một khi chúng tôi cố gắng decode hex, ta nhận được một văn bản vô nghĩa. **3]6o]`1vv1p\x7f**

```python3
data = bytes.fromhex("335d366f5d6031767631707f")
print(data)
```
```output
output: b'3]6o]`1vv1p\x7f'
```

- Bây giờ ta hãy nhớ lại một số manh mối từ mô tả thử thách. Cái đầu tiên là từ **Environmental**. Có một số biến do hệ thống xác định được gọi là **biến môi trường**.

- Để xem các biến môi trường trong một hệ thống, hãy sử dụng plugin `envars`. Kéo xuống ở đầu ra, chúng ta thấy một biến lạ có tên **Thanos** (Ah! vì vậy có lẽ đó là lý do tại sao nó được cung cấp trong mô tả.), giá trị của biến là **xor and password**

```sh
$ python2 vol.py -f Challenge.raw --profile=Win7SP1x86 envars
```
![img](https://github.com/Thuanle2401/CTF/blob/main/ForensisMemLabs/Lab0/lab0.5.png?raw=true)

**Bây giờ, chúng ta có tổng cộng 3 điều:**
- Văn bản vô nghĩa là kết quả của việc decode bằng hex
- xor
- password

**Hãy thử thử giải mã xor trên văn bản vô nghĩa `335d366f5d6031767631707f`**

```python3
data = bytes.fromhex("335d366f5d6031767631707f")

for k in range(1, 256):
    s = ''.join(chr(b ^ k) for b in data)
    if s.isprintable():
        print(f"[Key {k:3}] => {s}")
```
```output
output: [Key 2] => 1_4m_b3tt3r}
```
- Có tổng cộng 255 khả năng (tương ứng với 255 giá trị khóa XOR khác nhau), và nếu để ý, kết quả thứ 2 hiển thị một chuỗi đáng ngờ:
**1_4m_b3tt3r}** — Trông giống như phần sau của flag.
- Tiếp theo là "password" (mật khẩu). Sử dụng Volatility, chúng ta có thể trích xuất các hash mật khẩu NTLM (Windows) bằng plugin hashdump:
```sh
$ python2 vol.py -f Challenge.raw --profile=Win7SP1x86 hashdump
```

![img](https://github.com/Thuanle2401/CTF/blob/main/ForensisMemLabs/Lab0/lab0.7.png?raw=true)
- Lệnh này sẽ hiển thị danh sách các username và password hash có trong bộ nhớ RAM lúc dump. Trong số đó, hash mà chúng ta quan tâm là: `101da33f44e92c27835e64322d72e8b7`
- Giờ bạn có thể dùng các website bẻ khóa hash NTLM online (như Hashes.com...) để giải mã hash này thành chuỗi văn bản gốc (mật khẩu rõ ràng).
- Link: [hashes.com](https://hashes.com/en/decrypt/hash)

![img](https://github.com/Thuanle2401/CTF/blob/main/ForensisMemLabs/Lab0/lab0.6.png?raw=true)

**Kết quả sau khi giải mã:**

- Hash đó khi giải được cho ra phần đầu của flag: **flag{you_are_good_but**

- Ghép hai phần lại:

    + Phần đầu: **flag{you_are_good_but**

    + Phần sau (từ đoạn XOR hex): **1_4m_b3tt3r}**

👉 Kết quả hoàn chỉnh:

🎉 FLAG: **flag{you_are_good_but1_4m_b3tt3r}**

📚 Tài nguyên tham khảo:
[link](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)






