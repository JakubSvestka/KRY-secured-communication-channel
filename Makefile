ARCHIVE=xsvest05
DOCUMENTATION=
FILES=xsvest05.py dh.py ffs.py pipe.py Makefile

clean:
	rm -rf *.pyc
	rm -rf __pycache__
	rm -rf $(ARCHIVE).tar.gz
	rm -rf xsvest05_pipe
	rm -rf xsvest05_pipe_ack

archive:
	tar -pczf $(ARCHIVE).tar.gz $(FILES) $(DOCUMENTATION)