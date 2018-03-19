int func1() {return 1;}
int func2() {return 2;}
int func3() {return 3;}
int func4() {return 4;}
int func5() {return 5;}

int main() {
    int a[5];
    a[0] = func1();
    a[1] = func2();
    a[2] = func3();
    a[3] = func4();
    a[4] = func5();
    return a[3];
}
