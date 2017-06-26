import blescan
import sys

#GPIO.setmode(GPIO.BOARD)
#GPIO.setwarnings(False)
#GPIO.setup(18, GPIO.OUT)
#GPIO.setup(16, GPIO.OUT)



while True:	
	returnedList = blescan.parse_events(sock, 5)
	
				

				
