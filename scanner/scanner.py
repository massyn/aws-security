import argparse
import logging
import boto3

from collector import *
from policies import *

if __name__ == '__main__':
    logging.basicConfig(level = logging.INFO)
    logging.info('')
    logging.info('=====================================================')
    logging.info('')
    logging.info('  AWS Security Info - Cloud Security Scanner')
    logging.info('  by Phil Massyn - @massyn')
    logging.info('  https://www.awssecurity.info')
    logging.info('')
    logging.info('====================================================')
    logging.info('')
    logging.info('boto3 version = ' + boto3.__version__)

    parser = argparse.ArgumentParser(description='AWS Security Info - Cloud Security Scanner')

    C = collector()
    P = policy()

    C.arguments(parser)
    P.arguments(parser)

    args = parser.parse_args()

    C.execute(args)
    
    P.execute(args,C.last_file_name_read)
    
    logging.info(' ** All done **')