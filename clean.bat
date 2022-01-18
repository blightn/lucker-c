forfiles /p .vs\ /m ipch /c "cmd /c if @isdir==TRUE rd /s /q @file" /s

rd /s /q "Bins"

rd /s /q "Lucker\x86"
rd /s /q "Lucker\x64"
