# Documentation

## Generate documentation
To (re)generate the documentation, run the  following commands in the docs folder:
```
sphinx-apidoc ../src/aliro_actuator/ -o source/ -e
make html
make latexpdf
```

You might need to install latexmk to create the pdf documentation:
```
apt-get install latexmk
apt-get install texlive-latex-extra
```

If there are issues with accessing the html files, you might need to change the owners:
```
sudo chown -R <username> docs/build/html
```