package svarzee.gps.gpsoauth;

class Try<T> {
  private static final Try FAILURE = new Try();
  private final T value;

  private Try() {
    value = null;
  }

  private Try(T value) {
    if (value == null) throw new IllegalArgumentException();
    this.value = value;
  }

  public boolean isFailure() {
    return this == FAILURE;
  }

  public T get() {
    if (isFailure()) throw new IllegalStateException("Cannot get value from a failure.");
    return value;
  }

  public static <T> Try<T> of(T value) {
    return new Try<>(value);
  }

  public static <T> Try<T> failure() {
    @SuppressWarnings("unchecked")
    Try<T> failure = (Try<T>) FAILURE;
    return failure;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof Try)) {
      return false;
    }

    Try<?> aTry = (Try<?>) obj;

    return value != null ? value.equals(aTry.value) : aTry.value == null;

  }

  @Override
  public int hashCode() {
    return value != null ? value.hashCode() : 0;
  }
}
