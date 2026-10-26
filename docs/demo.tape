Output docs/demo.gif
Set FontFamily Hack
Set FontSize 17
Set Width 960
Set Height 700
Set Theme "Dracula"
Set WindowBar "Rings"
Set Padding 24

Type "python3 scripts/demo_make_inputs.py --out demo/Default"
Enter
Sleep 700ms
Sleep 400ms
Type "python3 scripts/import_cookies.py --dir demo/Default"
Enter
Sleep 700ms
Sleep 3s
Type "python3 scripts/import_passwords_cdp.py --dirs demo/Default"
Enter
Sleep 700ms
Sleep 5s
Sleep 8s
