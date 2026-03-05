# Fray Demo — GIF Recording
# Run: vhs docs/demo.tape

Output docs/demo.gif

Set Shell "zsh"
Set FontSize 14
Set Width 960
Set Height 540
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

Type "# Fray — WAF Security Testing Toolkit"
Enter
Sleep 1s

Type "fray scan http://testphp.vulnweb.com -c xss -m 3 --depth 2 --max-pages 8"
Enter
Sleep 30s

Sleep 3s
