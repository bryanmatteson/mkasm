# Run scripts/record-readme-demo.py with an Arm A64 XML corpus.
Output docs/assets/demo.gif
Set Shell "bash"
Set FontSize 18
Set Width 1280
Set Height 760
Set Padding 26
Set Framerate 10
Set TypingSpeed 20ms
Set Theme "Catppuccin Mocha"
Hide
Type@0ms `cd "$README_DEMO_DIR"; alias mkasm='"$README_DEMO_BIN"'; export PS1='mkasm ❯ '; unset PROMPT_COMMAND; clear`
Enter
Show
Type@0ms "# Generate a dependency-free A64 codec from Arm's XML"
Enter
Type 'mkasm --codegen go --output aarch64 "$MKASM_CORPUS"'
Enter
Sleep 8s
Hide
Type@0ms "clear"
Enter
Show
Type@0ms "# Use the generated encoder and decision-tree decoder"
Enter
Type "cat codec.go"
Enter
Sleep 5s
Type "(cd aarch64 && go run ../codec.go)"
Enter
Sleep 7s
