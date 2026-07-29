
describe('FormData', function() {
  // Skipped: depends on the external httpbin.org service, unreachable from CI.
  xit('should allow FormData posting', function () {
    return axios.postForm('http://httpbin.org/post', {
      a: 'foo',
      b: 'bar'
    }).then(({data}) => {
      expect(data.form).toEqual({
        a: 'foo',
        b: 'bar'
      });
    });
  });
})
