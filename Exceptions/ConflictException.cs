namespace Dermatologiya.Server.Exceptions
{
    public class ConflictException:Exception
    {
        //Ushbu sinf ikkita yoki undan ortiq resurslar o'rtasida to'qnashuv
        //(masalan, bir xil nomli elementlar mavjud bo'lganda) yuz berganda foydalanish uchun:
        public ConflictException()
        {
        }

        public ConflictException(string message)
            : base(message)
        {
        }

        public ConflictException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}
