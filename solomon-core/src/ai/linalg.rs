// solomon-core/src/ai/linalg.rs

use rand::Rng;

#[derive(Clone, Debug)]
pub struct Vector {
    pub data: Vec<f32>,
}

impl Vector {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0.0; size],
        }
    }

    pub fn from_vec(data: Vec<f32>) -> Self {
        Self { data }
    }

    pub fn add(&mut self, other: &Vector) {
        for (a, b) in self.data.iter_mut().zip(other.data.iter()) {
            *a += b;
        }
    }

    pub fn scale(&mut self, scalar: f32) {
        for a in self.data.iter_mut() {
            *a *= scalar;
        }
    }

    pub fn dot(&self, other: &Vector) -> f32 {
        self.data.iter().zip(other.data.iter()).map(|(a, b)| a * b).sum()
    }

    pub fn l2_norm(&self) -> f32 {
        self.dot(self).sqrt()
    }
}

#[derive(Clone, Debug)]
pub struct Matrix {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<f32>,
}

impl Matrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![0.0; rows * cols],
        }
    }

    pub fn xavier_init(rows: usize, cols: usize, rng: &mut impl Rng) -> Self {
        let mut mat = Self::new(rows, cols);
        let bound = (6.0 / (rows as f32 + cols as f32)).sqrt();
        for val in mat.data.iter_mut() {
            *val = rng.gen_range(-bound..bound);
        }
        mat
    }

    pub fn vector_mul(&self, vec: &Vector) -> Vector {
        assert_eq!(self.cols, vec.data.len(), "Matrix-Vector dimension mismatch");
        let mut out = Vector::new(self.rows);
        for i in 0..self.rows {
            let row_start = i * self.cols;
            let row_slice = &self.data[row_start..row_start + self.cols];
            let dot_product: f32 = row_slice.iter().zip(vec.data.iter()).map(|(a, b)| a * b).sum();
            out.data[i] = dot_product;
        }
        out
    }
}
