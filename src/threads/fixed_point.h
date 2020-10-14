#define F (1 << 14)
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))

int int_to_fp(int n);
int fp_to_int_round(int x);
int fp_to_int(int x);
int add_fp(int x, int y);
int add_mixed(int x, int n);
int sub_fp(int x, int y);
int sub_mixed(int x, int y);
int mult_fp(int x, int y);
int mult_mixed(int x, int y);
int div_fp(int x, int y);
int div_mixed(int x, int n);

/* convert integer value to floaing point value */
int int_to_fp(int n)
{
    return n * F;
}

/* convert floating point value to integer value (round to zero)*/
int fp_to_int(int x)
{
    return x / F;
}

/* convert floating point value to integer value (round)*/
int fp_to_int_round(int x)
{
    if (x > 0)
        return (x + F / 2) / F;
    else
        return (x - F / 2) / F;
}

/* add two floating point values */
int add_fp(int x, int y)
{
    return (x + y);
}

/* add a floating point value and a integer value */
int add_mixed(int x, int n)
{
    return (x + n * F);
}

/* subtract a floating point value y from a floating point value x */
int sub_fp(int x, int y)
{
    return (x - y);
}

/* subtract a integer value n from a floating point value x */
int sub_mixed(int x, int n)
{
    return (x - n * F);
}

/* multiply two floating point values */
int mult_fp(int x, int y)
{
    return (((int64_t)x) * y / F);
}

/* multiply a floating point value x by a integer value n */
int mult_mixed(int x, int n)
{
    return (x * n);
}

/* divide a floating point value x by a floating point value y */
int div_fp(int x, int y)
{
    return (((int64_t)x) * F / y);
}

/* divide a floating point value x by a integer value y */
int div_mixed(int x, int n)
{
    return (x / n);
}