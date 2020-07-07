const { src, dest } = require('gulp')
const concat = require('gulp-concat')
const postcss = require('gulp-postcss')

function tailwind() {
    return src('styles.css')
        .pipe(postcss([
            require('tailwindcss'),
            require('autoprefixer')
        ]))
        .pipe(concat('tailwind.css'))
        .pipe(dest('./css'))
}

exports.tailwind = tailwind