use crate::{Cache, Connection, FsCache, FunctionBindings, ResponseCache};
use http::Uri;
use mio::{net::TcpStream, Registry, Token};
use num_cpus;
use rustls::{ServerConfig, ServerSession, Session};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

#[allow(dead_code)]
pub struct Worker {
  handle: thread::JoinHandle<()>,
  id: usize,
}
impl Worker {
  pub fn new(
    id: usize,
    receiver: mpsc::Receiver<Job>,
    mut fs_cache: FsCache,
    mut response_cache: ResponseCache,
    mut bindings: Arc<FunctionBindings>,
    mut registry: Registry,
  ) -> Self {
    let mut connections = HashMap::new();

    let handle = thread::Builder::new()
      .name(format!("Worker: {}", id))
      .spawn(move || loop {
        let job = receiver.recv().unwrap();
        job(
          &mut fs_cache,
          &mut response_cache,
          &mut bindings,
          &mut connections,
          &registry,
        );
      })
      .expect("Failed to create thread!");

    Self { id, handle }
  }
}

type Job = Box<
  dyn FnOnce(
      &mut FsCache,
      &mut ResponseCache,
      &mut Arc<FunctionBindings>,
      &mut HashMap<Token, Connection>,
      &Registry,
    ) + Send
    + 'static,
>;

pub struct ThreadPool {
  workers: Vec<(Worker, mpsc::Sender<Job>)>,
  last_send: usize,
}

impl ThreadPool {
  pub fn new(
    size: usize,
    fs_cache: FsCache,
    response_cache: ResponseCache,
    bindings: Arc<FunctionBindings>,
    registry: &Registry,
  ) -> Self {
    assert!(size > 0);

    // let job_receiver = Arc::new(Mutex::new(job_receiver));
    let mut workers = Vec::with_capacity(size);
    for id in 0..size {
      let (job_sender, job_receiver) = mpsc::channel();
      workers.push((
        Worker::new(
          id,
          job_receiver,
          Arc::clone(&fs_cache),
          Arc::clone(&response_cache),
          Arc::clone(&bindings),
          registry.try_clone().expect("Failed to clone registry!"),
        ),
        job_sender,
      ));
    }
    Self {
      workers,
      last_send: 0,
    }
  }
  /// Guarantees a valid id, within range of worker vector
  fn next_send(&mut self) -> usize {
    if self.last_send + 1 >= self.workers.len() {
      self.last_send = 0;
      0
    } else {
      self.last_send += 1;
      self.last_send
    }
  }
  pub fn execute<F>(&mut self, f: F) -> usize
  where
    F: FnOnce(
        &mut FsCache,
        &mut ResponseCache,
        &mut Arc<FunctionBindings>,
        &mut HashMap<Token, Connection>,
        &Registry,
      ) + Send
      + 'static,
  {
    let job = Box::new(f);
    let id = self.next_send();
    let (_worker, sender) = self.workers.get(id).unwrap();
    sender.send(job).unwrap();
    id
  }
  /// # Errors
  /// If the worker id is incorrect.
  pub fn execute_on<F>(&self, worker_id: usize, f: F) -> Result<(), ()>
  where
    F: FnOnce(
        &mut FsCache,
        &mut ResponseCache,
        &mut Arc<FunctionBindings>,
        &mut HashMap<Token, Connection>,
        &Registry,
      ) + Send
      + 'static,
  {
    let job = Box::new(f);
    match self.workers.get(worker_id) {
      Some((_worker, sender)) => {
        sender.send(job).unwrap();
        Ok(())
      }
      None => Err(()),
    }
  }
}

pub struct HandlerPool {
  pool: ThreadPool,
  connections: HashMap<usize, usize>,
  server_config: Arc<ServerConfig>,
}
impl HandlerPool {
  pub fn new(
    config: Arc<ServerConfig>,
    fs_cache: FsCache,
    response_cache: ResponseCache,
    bindings: Arc<FunctionBindings>,
    registry: &Registry,
  ) -> Self {
    Self {
      pool: ThreadPool::new(
        num_cpus::get() as usize - 1,
        fs_cache,
        response_cache,
        bindings,
        registry,
      ),
      connections: HashMap::new(),
      server_config: config,
    }
  }

  pub fn accept(&mut self, mut socket: TcpStream, addr: SocketAddr, token: Token) {
    let config = Arc::clone(&self.server_config);
    let session = ServerSession::new(&config);
    let interest = {
      let rd = session.wants_read();
      let wr = session.wants_write();

      if rd && wr {
        mio::Interest::READABLE | mio::Interest::WRITABLE
      } else if wr {
        mio::Interest::WRITABLE
      } else {
        mio::Interest::READABLE
      }
    };
    self.connections.insert(
      token.0,
      self.pool.execute(
        move |fs_cache, response_cache, bindings, connections, registry| {
          println!("Accepting new connection from: {:?}", addr);

          let mut connection = Connection::new(
            socket,
            token,
            session,
            Arc::clone(&fs_cache),
            Arc::clone(&response_cache),
            Arc::clone(&bindings),
          );

          connection.register(registry);
          println!("Registered!");

          println!("Inserting with token {}", token.0);
          connections.insert(token, connection);
        },
      ),
    );
  }

  pub fn handle(&mut self, event: (bool, bool, Token)) -> Result<(), ()> {
    let token = event.2;

    match self.connections.get(&token.0) {
      Some(thread_id) => self
        .pool
        .execute_on(*thread_id, move |_, _, _, connections, registry| {
          if let Some(connection) = connections.get_mut(&token) {
            connection.ready(registry, (event.0, event.1));
            if connection.is_closed() {
              connections.remove(&token);
            }
          } else {
            eprintln!("Connection not found!");
          }
        }),
      None => {
        eprintln!("Connection not found! {:?}", token);
        Err(())
      }
    }
  }
}
