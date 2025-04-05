namespace Dermatologiya.Server.Exceptions
{
    public class BadRequestExeption:Exception
    {
        //Ushbu sinf foydalanuvchidan noto'g'ri yoki
        //yetarli bo'lmagan ma'lumotlar kelib tushganda foydalanish uchun

        public BadRequestExeption()
        {
        }

        public BadRequestExeption(string message)
            : base(message)
        {
        }

        public BadRequestExeption(string message, Exception inner)
            : base(message, inner)
        {

        }
    }
}
