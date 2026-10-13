# Server Health Manager

نسخه اول رابط گرافیکی PowerShell برای بررسی سلامت سرورهای Windows Server.

## اجرا

PowerShell را با Run as Administrator باز کنید و:

```powershell
cd "C:\Path\To\ServerHealthUI"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\ServerHealthManager.ps1"
```

یا فایل `Run-ServerHealthManager.bat` را با دسترسی Administrator اجرا کنید.

## Auto-Fix فعلی

فقط دو مورد اجازه تغییر خودکار دارند:

1. تنظیم Timezone:
   - `tzutil /s "Iran Standard Time_dstoff"`
   - `tzutil /s "Iran Standard Time"`
2. فعال‌سازی KMS:
   - `slmgr /skms "192.168.200.147"`
   - `slmgr /ato`

بعد از هر Fix وضعیت دوباره بررسی می‌شود.

## مواردی که عمداً خودکار تغییر نمی‌کنند

- Windows Update
- Restart / Reset Windows
- Domain Join
- Computer Name
- Local User Policy
- TLS
- VMware Tools
- Zabbix
- Splunk Forwarder
- Elastic/EDR
- حذف نرم‌افزار
- VSS Schedule

این موارد Check/Report می‌شوند و برای تغییر نیاز به بررسی و تأیید مسئول شبکه دارند.

## قبل از Production

در ابتدای `ServerHealthManager.ps1` این موارد باید با Policy واقعی شرکت تکمیل شوند:

- ApprovedStableOSBuilds
- ExpectedDomain
- ComputerNameRegex
- AllowedLocalUsers
- RequiredDisabledLocalUsers
- TLS policy
- VSS schedule

همچنین نام دقیق سرویس محصول EDR باید مشخص شود تا تشخیص آن دقیق‌تر شود.
