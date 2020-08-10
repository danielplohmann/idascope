rule EICAR {
	meta:
		author = "Daniel Plohmann <daniel.plohmann<at>fkie.fraunhofer.de"
		type = "info"
		description = "YARA rule for EICAR test file"

	strings: 
		$eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

	condition:
		$eicar
}
