import Extractor
import argparse


def create_arg_parser():
    parser = argparse.ArgumentParser(description="Description")
    parser.add_argument(
                    "conf_file",
                    help="The extractor configuration file"
                    )
    parser.add_argument(
                    "input_dir",
                    help="Input direcotry containing malwares"
                    )
    parser.add_argument(
                    "-o",
                    "--output-dir",
                    help="Output direcotry",
                    default="./out"
                    )

    return parser


if __name__ == '__main__':
    arg_parser = create_arg_parser()
    args = arg_parser.parse_args()

    # Getting args from the parser
    conf_file = args.conf_file
    in_folder = args.input_dir
    out_folder = args.output_dir

    # Making extraction
    extractor = Extractor.new(conf_file, in_folder, out_folder)
    extractor.extract_batch()
