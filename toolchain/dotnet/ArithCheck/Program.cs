// Minimal self-checking sample for the toolchain check (T4). Synthetic.
var failures = 0;

void Check(string name, bool ok)
{
    Console.WriteLine($"{(ok ? "ok" : "not ok")} - {name}");
    if (!ok) failures++;
}

Check("integer addition", 2 + 3 == 5);
Check("floor division", (int)Math.Floor(-7 / 2.0) == -4);
Check("banker's rounding of 2.5", Math.Round(2.5m, MidpointRounding.ToEven) == 2m);
Check("banker's rounding of 3.5", Math.Round(3.5m, MidpointRounding.ToEven) == 4m);

return failures == 0 ? 0 : 1;
