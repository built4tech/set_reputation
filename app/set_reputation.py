
import hashlib
import logging
import os
import sys
import time
import argparse
import csv


from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig

from dxltieclient import TieClient
from dxltieclient.constants import HashType, TrustLevel, FileType, FileProvider, ReputationProp

# Obtiene el nombre del directorio padre
parent_directory = os.path.dirname(os.getcwd())
CONFIG_FILE = parent_directory + os.sep + "config" + os.sep + "dxlclient.config"

# Reputation
REPUTATION_VALUES = {"KNOWN_TRUSTED_INSTALLER": 100, "KNOWN_TRUSTED": 99, "MOST_LIKELY_TRUSTED": 85, "MIGHT_BE_TRUSTED": 70,
                    "UNKNOWN": 50, "MIGHT_BE_MALICIOUS": 30, "MOST_LIKELY_MALICIOUS": 15, "KNOWN_MALICIOUS": 1, "NOT_SET": 0}            
# Configure local logger

# create logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)





def parseargs():
    '''
    Description: Function in charge of the CLI parameters
    Input:       No input
    Output:      Parsed arguments
    '''
    description = 'Set reputations to TIE Database'
    prog = 'set_reputation.py'
    usage = '\nset_reputation.py -i file_to_import [-dxlconfig] path_to_dxl_config_path [-force]'
    epilog = 'Carlos Munoz (carlos_munozgarrido@mcafee.com)\n%(prog)s 1.0 (03/2020)'

    parser = argparse.ArgumentParser(epilog=epilog, usage=usage, prog=prog, description=description, formatter_class=argparse.RawTextHelpFormatter)

   

    arg_help = "File to import"
    parser.add_argument('-import', required=True, default="", action='store', dest='import_file', help=arg_help,
                        metavar="")

    arg_help = "[Path to dxl config file]\n"
    arg_help = arg_help + "Default ./config/dxlclient.config"
    parser.add_argument('-dxlconfig', required=False, default=CONFIG_FILE, action='store', dest='dxl_config_file', help=arg_help,
                        metavar="")

    arg_help = "[Overwrites reputation if previously exists]\n"
    arg_help = arg_help + "Default False"
    parser.add_argument('-force', required=False, default=False, action='store_true', help=arg_help)


    parser.add_argument('--version', action='version', version='Carlos Munoz (carlos_munozgarrido@mcafee.com)\n%(prog)s 1.0 (03/2020)')

    return parser.parse_args()

def read_input_file(filename):
    ioc_list = []

    with open(filename, 'r') as csvfile:
        lines = csv.reader(csvfile)
        for line in lines:

            file_name    = ""
            sha1         = ""
            sha256       = ""
            md5          = ""
            reputation   = ""
            file_comment = ""

            try:
                file_name       = line[0]
                sha1            = line[1]
                sha256          = line[2]
                md5             = line[3]
                reputation      = line[4]
                file_comment    = line[5]

            except Exception as er:
                logger.error("Error - Reputation file Format error. Valid format: \n \
                             filename, sha1, sha256, md5, reputation, file_comment")
                sys.exit()

            ioc_list.append({"file_name": file_name, "sha1": sha1, "sha256": sha256, "md5": md5, "reputation": reputation, "file_comment": file_comment})

    return ioc_list

def file_exist(filename):
    return os.path.isfile(filename)

def set_reputation(dxl_config_file, ioc_list):
    # Create DXL configuration from file
    config = DxlClientConfig.create_dxl_config_from_file(dxl_config_file)

    # Create the client
    with DxlClient(config) as client:
        # Connect to the fabric
        client.connect()

        # Create the McAfee Threat Intelligence Exchange (TIE) client
        tie_client = TieClient(client)

        #
        # Hashes for the file whose reputation will be set.
        #
        # Replace the random values for the actual file hashes.
        #
        ioc_set    = 0
        ioc_error  = 0
        ioc_exist  = 0
        ioc_total  = 0

        for ioc in ioc_list:

            fileSHA1  =  hashlib.sha1(ioc["sha1"].encode('utf-8')).hexdigest()
            fileSHA256 = hashlib.sha256(ioc["sha256"].encode('utf-8')).hexdigest()
            fileMD5    = hashlib.md5(ioc["md5"].encode('utf-8')).hexdigest()

            hashes = {
                      HashType.MD5: fileMD5,
                      HashType.SHA1: fileSHA1,
                      HashType.SHA256: fileSHA256
                     }
            file_name    = ioc["file_name"]
            file_comment = ioc["file_comment"]
            reputation   = REPUTATION_VALUES[ioc["reputation"]]

            #
            # Request reputation for the file
            #
            reputations_dict = tie_client.get_file_reputation(hashes)
            #
            # Check if there's any definitive reputation (different to Not Set [0] and Unknown [50])
            #
            has_definitive_reputation = \
                any([rep[ReputationProp.TRUST_LEVEL] != TrustLevel.NOT_SET
                     and rep[ReputationProp.TRUST_LEVEL] != TrustLevel.UNKNOWN
                     for rep in reputations_dict.values()])

            # 
            # If there's a definitive reputation and we are not forcing the reputation aplication
            # Skip the application
            # 
            if has_definitive_reputation and force == False:
                logger.info("Information: There is a reputation from another provider for the file %s, \n \
                            External Reputation is not necessary." % file_name)
                ioc_exist = ioc_exist + 1
            else:
                #
                # Set the External reputation 
                #
                try:
                    logger.debug("Reputation %s"% reputation)
                    logger.debug("hashes %s"% hashes)
                    logger.debug("filename %s"% file_name)
                    logger.debug("comment %s"% file_comment)

                    tie_client.set_file_reputation(
                        reputation,
                        hashes,
                        #FileType.PEEXE,
                        filename=file_name,
                        comment=file_comment)


                    logger.info("Information: IoC %s sent to Threat Intelligence Exchange Database" % file_name)
                    ioc_set = ioc_set + 1
                except ValueError as e:
                    logger.error("Error sending IoC %s to Threat Intelligence Exchange Database" % file_name)
                    ioc_error = ioc_error + 1

            ioc_total = ioc_total + 1

        ioc_procesed = {"total_ioc_processed": ioc_total, "ioc_set": ioc_set, "ioc_exist": ioc_exist, "ioc_error": ioc_error}

        return (ioc_procesed)


def main():
    option = parseargs()

    file_to_import  = option.import_file
    dxl_config_file = option.dxl_config_file

    if not file_exist(file_to_import):
        logger.error("Reputation file to import doesn't exist. Check path: %s" % file_to_import)
        sys.exit()

    if not file_exist(dxl_config_file):
        logger.error("DXL configuration file doesn't exist. Check path: %s" % dxl_config_file)
        sys.exit()

    ioc_list = read_input_file(file_to_import)

    ioc_processed = set_reputation(dxl_config_file, ioc_list)

    logger.info("Processed IoC: %i"%ioc_processed["total_ioc_processed"])
    logger.info("Established IoC: %i"%ioc_processed["ioc_set"])
    logger.info("Already set IoC: %i"%ioc_processed["ioc_exist"])
    logger.info("Error, setting IoC: %i"%ioc_processed["ioc_error"])

if __name__ == "__main__":
    main()

