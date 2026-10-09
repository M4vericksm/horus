import logging
import sys


def setup_logger(name: str = "networkatlas") -> logging.Logger:
    """
    Configura e retorna um logger estruturado com saída para stdout.
    Idempotente: se o logger já estiver configurado, retorna o existente.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # Já configurado, evita handlers duplicados

    logger.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Evita que logs se propaguem para o root logger (evita duplicatas)
    logger.propagate = False

    return logger


# Logger padrão — importe diretamente nos outros módulos:
# from logger import logger
logger = setup_logger("networkatlas")
