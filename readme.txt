Виртуальное окружение
python -m venv venv

venv\Scripts\activate.bat
OR
.\venv\Scripts\Activate.ps1

Зависимости
pip install -r requirements.txt

Запуск
python main.py
OR
uvicorn main:app --reload