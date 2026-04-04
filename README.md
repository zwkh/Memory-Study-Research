学习项目：利用bytehook库，对so中的内存申请做监控，包括内存页的冷热情况和结构体的成员的冷热情况。
Tips:需要自编译内核，修改pagemap的flag（Android内核的保护机制，不允许读真实物理地址），才能获取真实的PFN。
<img width="691" height="236" alt="image" src="https://github.com/user-attachments/assets/9b6b9a66-f1ed-4962-b046-3e88d3078a34" />
