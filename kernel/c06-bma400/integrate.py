"""Emit the three independent diagnostic Kbuild inputs into a new directory."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
UNIT = Path("drivers/base/regmap")


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("unexpected regcache.c anchor: " + old)
    return source.replace(old, new)


def generate(tree, output):
    regcache = (tree/UNIT/"regcache.c").read_text()
    regcache = once(regcache, '#include "internal.h"', '#include "internal.h"\n\n'
                    'void kconc_c06_map_open(struct regmap *map);\n'
                    'void kconc_c06_map_closing(struct regmap *map);')
    regcache = once(regcache, '\tvoid *tmp_buf;\n\n\tif (map->cache_type == REGCACHE_NONE)',
                    '\tvoid *tmp_buf;\n\n\tkconc_c06_map_open(map);\n\tif (map->cache_type == REGCACHE_NONE)')
    regcache = once(regcache, 'void regcache_exit(struct regmap *map)\n{',
                    'void regcache_exit(struct regmap *map)\n{\n\tkconc_c06_map_closing(map);')
    values = {"regcache.c":regcache.encode(), "kconc-c06-observer.c":(HERE/"observer.c").read_bytes(),
              "Makefile":(tree/UNIT/"Makefile").read_bytes()+b"\nobj-y += kconc-c06-observer.o\n"}
    output.mkdir(parents=True, exist_ok=False)
    dest=output/UNIT
    dest.mkdir(parents=True)
    for name, data in values.items():
        (dest/name).write_bytes(data)
    hashes={str(UNIT/name):hashlib.sha256(data).hexdigest() for name,data in values.items()}
    (output/"files.json").write_text(json.dumps(hashes,indent=2)+"\n")


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    generate(args.tree,args.output)
