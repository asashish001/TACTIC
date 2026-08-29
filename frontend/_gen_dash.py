import pathlib, base64
data = pathlib.Path("_dash.b64").read_text()
html = base64.b64decode(data).decode("utf-8")
pathlib.Path("dashboard_image.html").write_text(html, encoding="utf-8")
print(f"Written {len(html)} bytes")
pass