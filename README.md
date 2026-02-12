# Oracle Panel

A web panel for Oracle Cloud instance IP operations (manual switch, monthly random-day schedule, Telegram notifications, account/key management).

## One-line deploy

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/yuanzhangdck/oracle-panel/main/install.sh)
```

After deployment:
- Open `http://<server-ip>:3001/login.html`
- Initial password is saved at `data/initial-admin-password.txt`
- Login and change password immediately in `API Keys -> 后台密码`

## Features

- API key upload/test/delete
- One-click change public IP
- Per-instance refresh + 30-minute cache
- Monthly random-day auto IP change
- Telegram notification (configurable from UI)
- Login/logout + password change

## Notes

- `data/settings.json`, database files, and uploaded key files are runtime data and should not be committed.
