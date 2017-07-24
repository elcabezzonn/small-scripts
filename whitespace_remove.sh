#I hate whitespace. if you add the file extension or last word of the space, this should place an underscore for each space
#!/bin/bash

read -ep "enter extension of file : " suffix

for f in *"$suffix"; do mv -- "$f" "${f// /_}"; done

