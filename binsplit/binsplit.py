import sys
import os
import tempfile

def splitFile(binFile, chunkSize):
	"""
	Split a binary file into smaller chunks based on the provided chunk size.
	"""
	f = open(binFile, 'rb')
	data = f.read()
	f.close()

	# Calculate the amount of chunks based on chunkSize
	bytes = len(data)
	noOfChunks = bytes / chunkSize
	if(bytes % chunkSize):
		noOfChunks += 1
	print "Splitting '{0}' ({1} chunks of {2} bytes)".format(binFile, str(noOfChunks), str(chunkSize))
	
	# # Create a temporary directoryh
	tmpDir = tempfile.gettempdir() + os.sep + "binSplit"
	print "Files will be stored in: {0}".format(tmpDir)
	
	# Write chunks to disk
	chunkNames = []
	counter = 0
	for i in range(0, bytes + 1, chunkSize):
		
		# If an existing chunk gets split off the /tmp path already exists
		if tmpDir not in binFile:
			chunk = tmpDir + os.sep + binFile + "_" + str(counter)
		else:
			chunk = binFile + "_" + str(counter)
			
		chunkNames.append(chunk)
		
		fh = open(chunk, 'wb')
		fh.write(data[i:i + chunkSize])
		fh.close()
		
		counter += 1
		
	return chunkNames
	
def help():
	"""
	Print out help information.
	"""
	print "Binary file splitter 1.0.0"
	print ""
	print "Usage: split.py <binary-file> <chunk-size>"

def main():
	# Capture and make sure all command-line arguments are valid
	if len(sys.argv) < 3:
		help();
		sys.exit()
		
	binFile = sys.argv[1]
	blockSize = int(sys.argv[2])
	
	if len(binFile) == 0 or blockSize <= 0:
		print "One or multiple provided arguments were to small"
		sys.exit()
	
	# Split binary file into chunks and write to /tmp
	chunks = splitFile(binFile, blockSize)
	
	# Display chunk information
	counter = 0
	for chunk in chunks:
		print "{0} - Offset: {1}".format(chunk, blockSize * counter)
		counter += 1

if __name__ == "__main__":
    main()
