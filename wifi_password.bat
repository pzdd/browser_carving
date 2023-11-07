@echo off
echo %date% %time%>>senhas.txt
echo %username%>>senhas.txt
echo - >>senhas.txt
netsh wlan show profile name=* key=clear >>senhas.txt
echo -------------------------------------------------------- >> senhas.txt
pause