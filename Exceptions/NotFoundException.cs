namespace Dermatologiya.Server.Exceptions
{
    public class NotFoundException:Exception
    {
        // Ushbu sinf resurs topilmagan holatlarda
        // (masalan, ma'lumotlar bazasida id bo'yicha qidirilayotgan obyekt mavjud bo'lmaganda) qo'llash uchun:

        public NotFoundException()
        {

        }

        public NotFoundException(string message)
            : base(message)
        {
        }

        public NotFoundException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
