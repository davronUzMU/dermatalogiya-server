namespace Dermatologiya.Server.Exceptions
{
    public class ValidationException:Exception
    {
        // Ushbu sinf foydalanuvchi tomonidan kiritilgan ma'lumotlar maxsus talablar
        // (masalan, format yoki qiymat doirasi)ga javob bermasa ishlatish uchun:

        public ValidationException()
        {

        }

        public ValidationException(string message)
            : base(message)
        {
        }

        public ValidationException(string message, Exception inner)
            : base(message, inner)
        {

        }

        public ValidationException(string message, string detailedError)
        : base($"{message}. Details: {detailedError}")
        {
        }

        // Bu erda validatsiya qilingan xatolarni saqlash uchun maxsus konstruktor
        public ValidationException(Dictionary<string, string> validationErrors)
            : base("One or more validation errors occurred.")
        {
            ValidationErrors = validationErrors;
        }

        public Dictionary<string, string> ValidationErrors { get; }

        public override string ToString()
        {
            var errors = ValidationErrors != null
                ? string.Join("; ", ValidationErrors.Select(kv => $"{kv.Key}: {kv.Value}"))
                : Message;
            return $"{base.ToString()}. Validation errors: {errors}";
        }
    }
}
