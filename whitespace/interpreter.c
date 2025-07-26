// gcc -fno-stack-protector interpreter.c -o interpreter

char *head = 0xDEADBEEF;

int main(){
  char print_buf[64];
  int stack[1024];
  int stack_ptr = 0;

  while (*head) {
    if (*head == ' ') {
      head++;
      if (*head == ' ') {
        head++;
        int num = 0;
        {
          int flag = 0;
          {
            char c = *head;
            head++;
            if (c == ' ') {
              flag = 1;
            } else if (c == '\t') {
              flag = -1;
            }
          }

          while (1) {
            char c = *head;
            head++;

            if (c == ' ') {
              num = num * 2 + 0;
            } else if (c == '\t') {
              num = num * 2 + 1;
            } else {
              break;
            }
          }
        }
        stack[stack_ptr] = num;
        stack_ptr++;
      } else {
        return;
      }
    } else if (*head == '\t' && *(head + 1) == '\n') {
      head += 2;
      if (*head == ' ' && *(head + 1) == ' ') {
        head += 2;
        stack_ptr--;
        print_buf[0] = stack[stack_ptr];
        print_buf[1] = '\0';
        __asm__ volatile("syscall" : : "a"(1), "D"(1), "S"(print_buf), "d"(1));
      } else {
        break;
      }
    } else {
      break;
    }
  }

  __asm__ volatile("mov $0xDEADBEEF, %rax");
  __asm__ volatile("jmp *%rax");

  return 0;
}
