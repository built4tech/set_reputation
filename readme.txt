Procedimiento para montar el entorno

1.- Clonamos el repositorio

	git clone https://github.com/built4tech/set_reputation.git

2.- pip install -r requirements.txt

3.- dxlclient provisionconfig config myserver client1 -u username -p password

	config 		--> Ruta donde se guardaran los ficheros de configuración (certificados, etc.)
	myserver 	--> Sustituir por la dirección IP o FQDN del servidor
	client1 	--> Nombre por el que se identifica al cliente que está siendo provisionado
	username 	--> ePO Username, El usuario debe ser administrador de ePO para poder provisionar un sistema
	password	--> ePO password
	[-t]		--> Opcional, puerto en caso de que el puerto por defecto (8443) no este siendo utilizado


	Ejemplo:

	(fcc) C:\Users\cmunoz\OneDrive - McAfee\git_repos\fcc>dxlclient provisionconfig config 192.168.1.90 devops_cl1 -u admin -p McAfee123!
	INFO: Saving csr file to config\client.csr
	INFO: Saving private key file to config\client.key
	INFO: Saving DXL config file to config\dxlclient.config
	INFO: Saving ca bundle file to config\ca-bundle.crt
	INFO: Saving client certificate file to config\client.crt

	Nota:
	El procedimiento anterior (punto 2), se debe repetir periódicamente en el caso de que se modifique la topología del fabric de DXL, por ejemplo añadiendo o eliminando brokers. Para ello se ejecutará el siguiente comando, su ejecución actualizará los certificados, para la posterior comunicación al fabric.

	dxlclient updateconfig config myserver -u username -p password


4.- Crear un fichero de texto tipo csv con el siguiente formato: file_name, sha1, sha256, md5, trust_level, file_comment

psservice64.exe,30496D2F60A2B10AE0DA39E5ADF107B3B43CCCCD,6DE3137B3088B2C2C311A540F9AAEB57E9FD38259CB18875F2380EE74EC1C7AF,029D745D114C0A69CF0CB12450CB7B74,KNOWN_MALICIOUS,"Submitted via set_reputation para FCC"
pslist.exe,FE41E35485D4C5B61EC555C1C38965F837759585,9927831E111AC61FD7645BF7EFA1787DB1A3E85B6F64A274CA04B213DC27FD08,2C23D6223D4AFF81AC137B6989BCE05C,KNOWN_MALICIOUS,"Submitted via set_reputation para FCC"


    +-------------------------+---------+---------------------------------------------------------------+
    | Trust Level             | Numeric | Description                                                   |
    +=========================+=========+===============================================================+
    | KNOWN_TRUSTED_INSTALLER |  100    | It is a trusted installer.                                    |
    +-------------------------+---------+---------------------------------------------------------------+
    | KNOWN_TRUSTED           |  99     | It is a trusted file or certificate.                          |
    +-------------------------+---------+---------------------------------------------------------------+
    | MOST_LIKELY_TRUSTED     |  85     | It is almost certain that the file or certificate is trusted. |
    +-------------------------+---------+---------------------------------------------------------------+
    | MIGHT_BE_TRUSTED        |  70     | It seems to be a benign file or certificate.                  |
    +-------------------------+---------+---------------------------------------------------------------+
    | UNKNOWN                 |  50     | The reputation provider has encountered the file or           |
    |                         |         | certificate before but the provider can't determine its       |
    |                         |         | reputation at the moment.                                     |
    +-------------------------+---------+---------------------------------------------------------------+
    | MIGHT_BE_MALICIOUS      |  30     | It seems to be a suspicious file or certificate.              |
    +-------------------------+---------+---------------------------------------------------------------+
    | MOST_LIKELY_MALICIOUS   |  15     | It is almost certain that the file or certificate is          |
    |                         |         | malicious.                                                    |
    +-------------------------+---------+---------------------------------------------------------------+
    | KNOWN_MALICIOUS         |  1      | It is a malicious file or certificate.                        |
    +-------------------------+---------+---------------------------------------------------------------+
    | NOT_SET                 |  0      | The file or certificate's reputation hasn't been determined   |
    |                         |         | yet.                                                          |
    +-------------------------+---------+---------------------------------------------------------------+
