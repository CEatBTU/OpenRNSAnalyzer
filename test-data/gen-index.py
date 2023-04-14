#!/usr/bin/env python3

with open('footer') as f:
    footer = f.read()

prefix = """
<head>
    <link rel="stylesheet" href="{1}/js-deps/bootstrap.min.css">
    <title>{0}</title>
    <meta charset="UTF-8">
</head>
<body>
    <script src="./bootstrap.min.js"></script>
    <div class="container">
        <div class="py-3 text-center"><h2>{0}<h2></div>
        <div class="row">
            <div class="col">
                <div class="list-group" id="select-fcn-list">
"""

item_format = """
<a class="list-group-item list-group-item-action" href="{0}">
        <div class="d-flex w-100 justify-content-between">
            {1}
            <span class="badge rounded-pill bg-{3}">{2}</span>
        </div>
</a>"""

suffix = """
                    </div>
                </div>
            </div>

</div>
{}
</body>
</html>
"""

archs = {
    "aarch64": {},
    "mips64": {},
    "powerpc64": {},
    "riscv64": {},
    "x86_64": {}
}

from glob import glob
from pathlib import Path

for k, v in archs.items():
    all_indexes = True
    passed = 0
    failed = 0
    with open(f'{k}/index.html', 'w') as f:
        f.write(prefix.format(f'Architecture {k}', '../..'))
        print(f'{k}/output-{k}-*.c/')
        for i in glob(f'{k}/output-{k}-*.c/'):
            try:
                idx = list(Path(i).glob('index*.html'))[0]
                tag = "PASS"
                color = "success"
                passed += 1
            except:
                logfile_path = str(i).removesuffix('/') + ('.log')
                with open(logfile_path) as logfile:
                    if 'panicked' in logfile.read():
                        tag = "🐛 Fail"
                        color = "danger"
                    else:
                        tag = "🕑"
                        color = "warning"
                idx = Path("./" + logfile_path.removeprefix('{k}/'))
                all_indexes = False
                failed += 1
            f.write(item_format.format('./' + str(idx).removeprefix(f'{k}'), i.removeprefix(f'{k}/output-{k}-').removesuffix('.c/'), tag, color))
        f.write(suffix.format(footer))
        archs[k]['all_indexes'] = all_indexes
        archs[k]['passed'] = passed
        archs[k]['failed'] = failed

with open('index.html', 'w') as f:
    f.write(prefix.format('Architectures', '..'))
    for k, v in archs.items():
        if v['all_indexes']:
            tag = "✓ " + str(v['passed']) + ' / ' + str(v['passed'] + v['failed'])
            color = "success"
        else:
            tag = "⚠ " + str(v['passed']) + ' / ' + str(v['passed'] + v['failed'])
            color = "primary"
        f.write(item_format.format(f'{k}/index.html', k, tag, color))
    f.write(suffix.format(footer))
