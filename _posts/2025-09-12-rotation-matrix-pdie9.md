---
title: 旋转矩阵
date: '2025-09-12 17:11:04'
permalink: /post/rotation-matrix-pdie9.html
layout: post
published: true
---



# 旋转矩阵

给你一幅由 N × N 矩阵表示的图像，其中每个像素的大小为 4 字节。请你设计一种算法，将图像旋转 90 度。

不占用额外内存空间能否做到？

 

示例 1：

```c++
给定 matrix =
[
  [1,2,3],
  [4,5,6],
  [7,8,9]
],

原地旋转输入矩阵，使其变为:
[
  [7,4,1],
  [8,5,2],
  [9,6,3]
]
```

示例 2：

```c++
给定 matrix =
[
  [ 5, 1, 9,11],
  [ 2, 4, 8,10],
  [13, 3, 6, 7],
  [15,14,12,16]
],

原地旋转输入矩阵，使其变为:
[
  [15,13, 2, 5],
  [14, 3, 4, 1],
  [12, 6, 8, 9],
  [16, 7,10,11]
]
```

注意：本题与主站 48 题相同：https://leetcode-cn.com/problems/rotate-image/

相关标签

C++

## 解

旋转90°，说到底是读取数据的顺序发生了规律性变化。一开始1，2，3，变成了7，4，1，对应的下标是[0][0]、[0][1]、[0][2]，变成了[2][0]、[1][0]、[0][0]，其他行以此类推。

漏看了个条件，不占用额外内存空间

那就是需要在原有的数组基础上进行转换。

由于鄙人才疏学浅，最终去网上看了别人的分析

https://blog.csdn.net/afei__/article/details/84242702

这一篇就非常好，他的思路如下图

![image](assets/image-20250913091157-3rkiig4.png)

由于题目给出的矩阵都是方阵，所以旋转90°，实际上是将[n][0]，移动到[0,n]的位置，[0][0]移动到[0,n]，[0][n]移动到[n][n]，[n][n]移动到[n][0]。

每次循环都只旋转一个环，假设矩阵为n*n，那么环数为n/2。

```c++
#include<iostream>
#include<algorithm>
#include<vector>

using namespace std;
class Solution {
public:
    void rotate(vector<vector<int>>& matrix) {
        int n = matrix.size();
        int start = 0, end = 0;
        for (int i = 0;i < n / 2;i++) {
            start = i;
            end = n - i-1;
            int temp;
            for (int j = 0;j < end-start;j++) {
                temp = matrix[start+j][end];
                matrix[start + j][end] = matrix[start][start + j];
                matrix[start][start + j] = matrix[end - j][start];
                matrix[end-j][start] = matrix[end][end-j];
                matrix[end][end - j] = temp;
            }
        }
    }
};

int main() {
    vector<vector<int>>v = { { 5,  1,  9,  11 },
                               { 2,  4,  8,  10 },
                               { 13, 3,  6,  7  },
                               { 15, 14, 12, 16 } };
    Solution* s = new Solution();
    s->rotate(v);
    for (int i = 0;i < v.size();i++) {
        for (int j = 0;j < v.size();j++) {
            cout << v[i][j]<<" ";
        }
        cout << endl;
    }
    return 0;
}
```
