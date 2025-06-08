# MemLabs - Lab3
---
# Challenge Description
> Một tập lệnh độc hại đã mã hóa một thông tin rất bí mật mà tôi có trên hệ thống của mình. Bạn có thể khôi phục thông tin đó cho tôi được không?

Bạn cần thêm 1 tool nữa để hỗ trợ cho bài Lab này

`$ sudo apt install steghide`

The flag format: inctf{s0me_l33t_Str1ng}

Challenge file: [MemLabs-Lab3](https://mega.nz/#!2ohlTAzL!1T5iGzhUWdn88zS1yrDJA06yUouZxC-VstzXFSRuzVg)

---
# Solution
- Đầu tiên, chúng ta cần xác định hệ điều hành của memory image.

`$ python2 vol.py -f ~/volatility/Memlabs/Lab3/MemoryDump_Lab3.raw imageinfo`           
<pre>
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : <b style="color: red">Win7SP1x86_23418</b>, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/kali/volatility/Memlabs/Lab3/MemoryDump_Lab3.raw)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82742c68L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x82743d00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2018-09-30 09:47:54 UTC+0000
     Image local date and time : 2018-09-30 15:17:54 +0530
</pre>


- Tiếp theo, hãy kiểm tra command line của các tiến trình đang chạy.

`$ python2 vol.py -f ~/volatility/Memlabs/Lab3/MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 cmdline`
<pre>Volatility Foundation Volatility Framework 2.6.1
.........................
************************************************************************
notepad.exe pid:   <b style="color: red" style="color: red">3736</b>
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\hello\Desktop\evilscript.py
************************************************************************
notepad.exe pid:   <b style="color: red">3432</b>
Command line : "C:\Windows\system32\NOTEPAD.EXE" C:\Users\hello\Desktop\vip.txt
</pre>

Chúng ta có hai tệp: `evilscript.py`, `vip.txt` trông giống như một tệp quan trọng.

- Bây giờ ta sẽ tìm kiếm 2 tệp này trong bộ nhớ

`$ python2 vol.py -f ~/volatility/Memlabs/Lab3/MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 filescan | egrep "evilscript.py|vip.txt"`

<pre>
Volatility Foundation Volatility Framework 2.6.1
0x000000003de1b5f0      8      0 R--rw- \Device\HarddiskVolume2\Users\hello\Desktop\evilscript.py.py
0x000000003e727490      2      0 RW-rw- \Device\HarddiskVolume2\Users\hello\AppData\Roaming\Microsoft\Windows\Recent\evilscript.py.lnk
0x000000003e727e50      8      0 -W-rw- \Device\HarddiskVolume2\Users\hello\Desktop\vip.txt
</pre>

- Hiện tại, ta đã có offsets của 2 tệp, hãy dump chúng.
`$ python2 vol.py -f ~/volatility/Memlabs/Lab3/MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003de1b5f0 -D ./Memlabs/Lab3`

- File python đã dump:
<pre>
┌──(kali㉿kali)-[~/volatility/Memlabs/Lab3]
└─$ ls
file.None.0xbc2b6af0.dat  MemLabs-Lab3.7z  MemoryDump_Lab3.raw

┌──(kali㉿kali)-[~/volatility/Memlabs/Lab3]
└─$ cat file.None.0xbc2b6af0.dat
<b style="color: red"> 
import sys
import string
def xor(s):
        a = ''.join(chr(ord(i)^3) for i in s)
        return a
def encoder(x):
        return x.encode("base64")
if __name__ == "__main__":
        f = open("C:\\Users\\hello\\Desktop\\vip.txt", "w")
        arr = sys.argv[1]
        arr = encoder(xor(arr))
        f.write(arr)
        f.close()
</b>
</pre>

- Tập lệnh độc hại này đang XOR tệp `vip.txt` với từng ký tự rồi mã hóa Base64.
<pre>
┌──(kali㉿kali)-[~/volatility]
└─$ python2 vol.py -f ~/volatility/Memlabs/Lab3/MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003e727e50 -D ./Memlabs/Lab3
Volatility Foundation Volatility Framework 2.6.1
DataSectionObject 0x3e727e50   None   \Device\HarddiskVolume2\Users\hello\Desktop\vip.txt
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/volatility]
└─$ cd Memlabs/Lab3
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/volatility/Memlabs/Lab3]
└─$ ls
file.None.0x83e52420.dat  file.None.0xbc2b6af0.dat  MemLabs-Lab3.7z  MemoryDump_Lab3.raw
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/volatility/Memlabs/Lab3]
└─$ cat file.None.0x83e52420.dat 
<b style="color: red">am1gd2V4M20wXGs3b2U=</b>

</pre>

- Và đây là nội dung của tệp văn bản đã dump:
`am1gd2V4M20wXGs3b2U=`
- Vì vậy, trước tiên chúng ta cần giải mã Base64 rồi XOR lại với từng ký tự để lấy lại văn bản gốc.

<pre>
$ python
>>> s = 'am1gd2V4M20wXGs3b2U='
>>> s = s.decode('base64')
>>> ''.join(chr(ord(i)^3) for i in s)
inctf{0n3_h4lf
</pre>

>Part 1: inctf{0n3_h4lf

- Bây giờ chúng ta đã có 1 phần của flag, hãy cùng tìm phần còn lại.
- Thử tìm hiểu về `Steghide`:
	- `Steghide` là một chương trình ẩn dữ liệu có khả năng ẩn dữ liệu trong hình ảnh và tệp âm thanh và hỗ trợ hình ảnh JPEG và BMP, vì vậy ta thử tìm kiếm hình ảnh JPEG trong bộ nhớ.
<pre>
┌──(kali㉿kali)-[~/volatility]
└─$ python2 vol.py -f ~/volatility/Memlabs/Lab3/MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 filescan | grep ".jpeg"                          
Volatility Foundation Volatility Framework 2.6.1
0x0000000004f34148      2      0 RW---- \Device\HarddiskVolume2\Users\hello\Desktop\<b style="color: red">suspision1.jpeg</b>
</pre>

- Bây giờ, ta sẽ thử dump nó:

![img](https://n1ght-w0lf.github.io/assets/images/ctf-writeups/memlabs/lab3/2.jpeg)

- Ta sẽ kiểm tra xem file ảnh này có ẩn chứa điều gì với `steghide`:
<pre>
┌──(kali㉿kali)-[~/volatility/Memlabs/Lab3]
└─$ steghide extract -sf file.None.0x843fcf38.dat 
Enter passphrase: 
</pre>

- Yêu cầu mật khẩu để giải nén vậy ta thử lấy phần đầu của flag nhập vào.

<pre>
┌──(kali㉿kali)-[~/volatility/Memlabs/Lab3]
└─$ steghide extract -sf file.None.0x843fcf38.dat
Enter passphrase: 
wrote extracted data to "secret text".
</pre>

- Đọc nội dung `secret text` ta nhận được phần 2 của flag:

<pre>
┌──(kali㉿kali)-[~/volatility/Memlabs/Lab3]
└─$ cat 'secret text'           
_1s_n0t_3n0ugh}
</pre>

<b>FLAG: inctf{0n3_h4lf_1s_n0t_3n0ugh} </b>