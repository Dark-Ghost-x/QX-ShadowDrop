معرفی ابزار QX-ShadowDrop

QX-ShadowDrop یک اسکنر امنیتی سبک و قابل تنظیم برای تست آسیب‌پذیری‌های وب‌سایت‌هاست. این ابزار شامل ۱۸ ماژول مختلف است که هرکدام برای شناسایی نوع خاصی از آسیب‌پذیری طراحی شده‌اند. یکی از قابلیت‌های مهم این ابزار، پشتیبانی از پیلودهای سفارشی (Custom Payloads) است؛ یعنی شما می‌توانید تست‌های دلخواه خود را روی هدف اجرا کنید.

 این نسخه از ابزار در حالت بتا قرار دارد و ممکن است برخی ماژول‌ها به‌طور کامل یا دقیق عمل نکنند. اما در نسخه‌های آینده، به‌روزرسانی‌های چشم‌گیری ارائه خواهد شد.

 نصب و راه‌اندازی (Termux)

pkg update && pkg upgrade
pkg install python git
git clone https://github.com/Dark-Ghost-x/QX-ShadowDrop.git
cd QX-ShadowDrop
pip install -r requirements.txt

برای کاربران لینوکس.
sudo apt update && sudo apt upgrade
sudo apt install python3 python3-pip git

git clone https://github.com/Dark-Ghost-x/QX-ShadowDrop.git
cd QX-ShadowDrop
pip install -r requirements.txt

 نحوه اجرای ابزار
اجرای کامل همه ماژول‌ها:
python3 run.py -t https://example.com --stealth


توجه: اجرای همه ماژول‌ها ممکن است زمان‌بر باشد (۳۰ تا ۶۰ دقیقه). پیشنهاد می‌شود ماژول‌ها را به‌صورت تکی اجرا کنید:
اجرای یک ماژول خاص:
python3 run.py -t https://example.com -m headers --stealth


 لیست ماژول‌های موجود
csrf
lfi
sql_injection
xss
directory_traversal
open_redirect
subdomain_enum
admin_panels
download
port_scan
tech_stack
clickjacking
form_bruteforce
rfi
command_injection
headers
sensitive_info
wayback_scraper


 برای اجرای هر ماژول، از دستور زیر استفاده کنید:
python3 run.py -t https://example.com -m نام_ماژول --stealth


حالت‌های قابل استفاده

--debug
نمایش لاگ‌های داخلی و خطاها


--stealth
اجرای مخفی با ردپای کم


--aggressive
اجرای تهاجمی با تست‌های سنگین


--verbose
نمایش کامل جزئیات خروجی




 می‌توانید حالت‌ها را ترکیب کنید:
python3 run.py -t https://example.com -m headers --stealth --debug


 پشتیبانی

در صورت بروز مشکل در نصب یا اجرای ابزار، می‌توانید از طریق تلگرام با توسعه‌دهنده در ارتباط باشید تا راهنمایی لازم را دریافت کنید.

⚠️ هشدار قانونی

این ابزار صرفاً برای آموزش، پژوهش، و تست‌های قانونی طراحی شده است. استفاده از آن برای نفوذ غیرمجاز به سیستم‌ها، سرورها یا وب‌سایت‌ها غیرقانونی بوده و مسئولیت هرگونه سوءاستفاده از آن بر عهده کاربر می‌باشد. توسعه‌دهنده هیچ‌گونه مسئولیتی در قبال استفاده نادرست ندارد.
::::::::::::::::::::::::::::::::::::::
Introduction to QX-ShadowDrop

QX-ShadowDrop is a lightweight and customizable vulnerability scanner designed for testing the security of websites. It features 18 distinct modules, each tailored to detect specific types of vulnerabilities. One of its standout features is support for custom payloads, allowing users to craft and deploy their own test inputs against target systems.

This is a beta release, and some modules may not function fully or accurately under all conditions. However, the tool is actively under development and will receive significant improvements in future updates.

 Installation Guide (Termux)

To install QX-ShadowDrop on Termux:
pkg update && pkg upgrade
pkg install python git
git clone https://github.com/Dark-Ghost-x/QX-ShadowDrop.git
cd QX-ShadowDrop
pip install -r requirements.txt

Linux:
sudo apt update && sudo apt upgrade
sudo apt install python3 python3-pip git

git clone https://github.com/Dark-Ghost-x/QX-ShadowDrop.git
cd QX-ShadowDrop
pip install -r requirements.txt

 How to Use the Tool
Run all modules:
python3 run.py -t https://example.com --stealth


 Note: Running all modules may take time (30 to 60 minutes depending on the target). It is recommended to run modules individually for faster and more focused results.
Run a specific module:
python3 run.py -t https://example.com -m headers --stealth


 Available Modules
csrf
lfi
sql_injection
xss
directory_traversal
open_redirect
subdomain_enum
admin_panels
download
port_scan
tech_stack
clickjacking
form_bruteforce
rfi
command_injection
headers
sensitive_info
wayback_scraper


To run a specific module:
python3 run.py -t https://example.com -m <module_name> --stealth


 Execution Modes



Flag
Description




--debug
Displays internal logs and error messages


--stealth
Runs in stealth mode with minimal footprint


--aggressive
Executes deep and intensive scans


--verbose
Shows detailed output and scan results




You can combine multiple flags for enhanced control:
python3 run.py -t https://example.com -m headers --stealth --debug


 Support

If you encounter issues during installation or usage, feel free to contact the developer via Telegram for assistance and troubleshooting.

⚠️ Legal Disclaimer

This tool is intended strictly for educational, research, and authorized penetration testing purposes. Unauthorized use against systems, servers, or websites is illegal, and the user bears full responsibility for any misuse. The developer assumes no liability for improper or unethical use of this tool.
