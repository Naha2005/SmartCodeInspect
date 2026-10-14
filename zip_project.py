import os, zipfile, sys
from pathlib import Path
from datetime import datetime

EXCLUDE_DIRS = {
    'venv', '.venv', 'env', '.env', 'virtualenv', 'conda-env',
    '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache',
    'build', 'dist', '.eggs',
    'node_modules', '.next', '.nuxt', '.turbo', '.cache',
    '.git', '.svn', '.hg', '.idea', '.vscode',
}

EXCLUDE_EXTS = {
    '.pyc', '.pyo', '.pyd',
    '.log',
    '.tmp', '.swp', '.swo',
    '.zip',
}

def should_exclude_dir(dir_name):
    return dir_name.lower() in {d.lower() for d in EXCLUDE_DIRS}

def should_exclude_file(file_name):
    nl = file_name.lower()
    for ext in EXCLUDE_EXTS:
        if nl.endswith(ext.lower()):
            return True
    return nl in {'.ds_store', 'thumbs.db'}

def create_clean_zip(source_dir, output_zip_path=None):
    source_path = Path(source_dir).resolve()
    if not source_path.exists() or not source_path.is_dir():
        raise ValueError(f'Source folder does not exist: {source_dir}')

    if not output_zip_path:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_zip_path = source_path / f'{source_path.name}_clean_{ts}.zip'
    else:
        output_zip_path = Path(output_zip_path).resolve()

    print(f'Packaging: {source_path}')
    print(f'Zip File:  {output_zip_path}')
    print('-' * 50)

    total_files = 0
    skipped_files = 0

    with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(source_path):
            dirs[:] = [d for d in dirs if not should_exclude_dir(d)]
            for file in files:
                if should_exclude_file(file):
                    skipped_files += 1
                    continue
                abs_file_path = Path(root) / file
                if abs_file_path.resolve() == output_zip_path.resolve():
                    continue
                rel_path = abs_file_path.relative_to(source_path)
                zipf.write(abs_file_path, arcname=str(rel_path))
                total_files += 1

    file_size_mb = output_zip_path.stat().st_size / (1024 * 1024)
    print('-' * 50)
    print('Clean ZIP created successfully!')
    print(f'Files packaged: {total_files}')
    print(f'Files skipped:  {skipped_files}')
    print(f'ZIP size:       {file_size_mb:.2f} MB')
    print(f'Saved to:       {output_zip_path}')
    return str(output_zip_path)

if __name__ == '__main__':
    default_target = r'c:\Users\User\Desktop\SmartCodeInspect'
    target = sys.argv[1] if len(sys.argv) > 1 else default_target
    create_clean_zip(target)
