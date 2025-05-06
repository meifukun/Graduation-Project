import yaml


class Config:
    """Convert a ``dict`` into a ``Class``"""

    def __init__(self, entries: dict = {}):
        for k, v in entries.items():
            self.__dict__[k] = v


def load_config(file_path: str) -> dict:
    """
    Load configuration from a YAML file

    Parameters
    ----------
    file_path : str
        Path to the config file (in YAML format)

    Returns
    -------
    config : dict
        Configuration settings
    """
    f = open(file_path, 'r', encoding='utf-8')
    config = yaml.load(f.read(), Loader=yaml.FullLoader)
    return config


def parse_opt(file_path: str) -> Config:
    config_dict = load_config(file_path)
    config = Config(config_dict)
    return config


if __name__ == '__main__':
    test = parse_opt("../config/nodevideo.yaml")
    print(test.rechara)
